-- Individual identity and role administration. No engine tables or policies change.
CREATE SCHEMA aegisops_auth;
REVOKE ALL ON SCHEMA aegisops_auth FROM PUBLIC, anon;
GRANT USAGE ON SCHEMA aegisops_auth TO authenticated;

CREATE TABLE aegisops_auth.role_changes (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 actor_id uuid NOT NULL,
 target_id uuid NOT NULL,
 old_role text NOT NULL,
 new_role text NOT NULL,
 changed_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE aegisops_auth.role_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegisops_auth.role_changes FORCE ROW LEVEL SECURITY;
REVOKE ALL ON aegisops_auth.role_changes FROM PUBLIC, anon, authenticated;
CREATE FUNCTION aegisops_auth.reject_mutation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN RAISE EXCEPTION 'append-only role history' USING ERRCODE='42501'; END $$;
CREATE TRIGGER immutable_roles BEFORE UPDATE OR DELETE ON aegisops_auth.role_changes
FOR EACH ROW EXECUTE FUNCTION aegisops_auth.reject_mutation();
CREATE TRIGGER immutable_role_truncate BEFORE TRUNCATE ON aegisops_auth.role_changes
FOR EACH STATEMENT EXECUTE FUNCTION aegisops_auth.reject_mutation();

-- These helpers need narrow access to auth.users/auth.sessions. They are private,
-- have fixed search paths and require auth.uid() plus a current session.
CREATE FUNCTION aegisops_auth.identity()
RETURNS TABLE(user_id uuid, email text, role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
 SELECT u.id, u.email::text,
   CASE WHEN u.raw_app_meta_data->>'aegisops_role' IN ('viewer','operator','approver','admin')
        THEN u.raw_app_meta_data->>'aegisops_role' ELSE 'viewer' END
 FROM auth.users u JOIN auth.sessions s ON s.user_id=u.id
 WHERE u.id=auth.uid() AND s.id::text=auth.jwt()->>'session_id'
   AND auth.jwt()->>'role'='authenticated'
   AND (auth.jwt()->>'exp')::double precision > extract(epoch FROM now())
   AND u.email_confirmed_at IS NOT NULL AND NOT coalesce(u.is_anonymous,false)
   AND (u.banned_until IS NULL OR u.banned_until<=now())
   AND (s.not_after IS NULL OR s.not_after>now())
$$;

CREATE FUNCTION aegisops_auth.users()
RETURNS TABLE(user_id uuid,email text,role text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = '' AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM aegisops_auth.identity() i WHERE i.role='admin') THEN
   RAISE EXCEPTION 'Admin required' USING ERRCODE='42501';
 END IF;
 RETURN QUERY SELECT u.id,u.email::text,
   CASE WHEN u.raw_app_meta_data->>'aegisops_role' IN ('viewer','operator','approver','admin')
        THEN u.raw_app_meta_data->>'aegisops_role' ELSE 'viewer' END
 FROM auth.users u WHERE NOT coalesce(u.is_anonymous,false) AND u.email IS NOT NULL
 ORDER BY u.created_at DESC LIMIT 100;
END $$;

CREATE FUNCTION aegisops_auth.set_role(target_user uuid,new_role text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE actor uuid; previous text;
BEGIN
 SELECT i.user_id INTO actor FROM aegisops_auth.identity() i WHERE i.role='admin';
 IF actor IS NULL THEN RAISE EXCEPTION 'Admin required' USING ERRCODE='42501'; END IF;
 IF target_user=actor THEN RAISE EXCEPTION 'You cannot change your own role' USING ERRCODE='42501'; END IF;
 IF new_role IS NULL OR new_role NOT IN ('viewer','operator','approver','admin') THEN
   RAISE EXCEPTION 'Unknown role' USING ERRCODE='22023';
 END IF;
 SELECT coalesce(u.raw_app_meta_data->>'aegisops_role','viewer') INTO previous
 FROM auth.users u WHERE u.id=target_user AND NOT coalesce(u.is_anonymous,false) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Account not found' USING ERRCODE='22023'; END IF;
 UPDATE auth.users SET raw_app_meta_data=jsonb_set(coalesce(raw_app_meta_data,'{}'::jsonb),'{aegisops_role}',to_jsonb(new_role)) WHERE id=target_user;
 INSERT INTO aegisops_auth.role_changes(actor_id,target_id,old_role,new_role) VALUES(actor,target_user,previous,new_role);
END $$;

-- Public API wrappers are invokers. The privileged implementations stay private.
CREATE FUNCTION public.aegisops_identity() RETURNS TABLE(user_id uuid,email text,role text)
LANGUAGE sql STABLE SECURITY INVOKER SET search_path='' AS $$ SELECT * FROM aegisops_auth.identity() $$;
CREATE FUNCTION public.aegisops_users() RETURNS TABLE(user_id uuid,email text,role text)
LANGUAGE sql STABLE SECURITY INVOKER SET search_path='' AS $$ SELECT * FROM aegisops_auth.users() $$;
CREATE FUNCTION public.aegisops_set_role(target_user uuid,new_role text) RETURNS void
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT aegisops_auth.set_role(target_user,new_role) $$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aegisops_auth FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION aegisops_auth.identity(),aegisops_auth.users(),aegisops_auth.set_role(uuid,text) TO authenticated;
REVOKE ALL ON FUNCTION public.aegisops_identity(),public.aegisops_users(),public.aegisops_set_role(uuid,text) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.aegisops_identity(),public.aegisops_users(),public.aegisops_set_role(uuid,text) TO authenticated;
NOTIFY pgrst, 'reload schema';
