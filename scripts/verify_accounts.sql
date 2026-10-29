-- Administrative integration probe. Fake accounts, sessions, grants and audit rows
-- exist only inside this transaction. No mail is sent and nothing is committed.
BEGIN;
INSERT INTO auth.users(id,email,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at)
VALUES ('00000000-0000-4000-a000-000000000001','aegis-viewer-probe@example.invalid',now(),'{}','{"aegisops_role":"admin"}',now()),
       ('00000000-0000-4000-a000-000000000002','aegis-admin-probe@example.invalid',now(),'{"aegisops_role":"admin"}','{}',now());
INSERT INTO auth.sessions(id,user_id,created_at,not_after)
VALUES ('00000000-0000-4000-b000-000000000001','00000000-0000-4000-a000-000000000001',now(),now()+interval '1 hour'),
       ('00000000-0000-4000-b000-000000000002','00000000-0000-4000-a000-000000000002',now(),now()+interval '1 hour');
GRANT authenticated TO postgres WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-a000-000000000001',true);
SELECT set_config('request.jwt.claims','{"sub":"00000000-0000-4000-a000-000000000001","session_id":"00000000-0000-4000-b000-000000000001","role":"authenticated","exp":4102444800,"app_metadata":{"aegisops_role":"admin"}}',true);
DO $$
BEGIN
 IF (SELECT role FROM public.aegisops_identity()) <> 'viewer' THEN RAISE EXCEPTION 'Metadata escalation'; END IF;
 BEGIN
  PERFORM public.aegisops_users(); RAISE EXCEPTION 'Viewer read admin list';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  PERFORM public.aegisops_set_role('00000000-0000-4000-a000-000000000001','admin'); RAISE EXCEPTION 'Viewer escalated';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-a000-000000000002',true);
SELECT set_config('request.jwt.claims','{"sub":"00000000-0000-4000-a000-000000000002","session_id":"00000000-0000-4000-b000-000000000002","role":"authenticated","exp":4102444800}',true);
DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM public.aegisops_users() WHERE user_id='00000000-0000-4000-a000-000000000001') THEN RAISE EXCEPTION 'Admin listing failed'; END IF;
 PERFORM public.aegisops_set_role('00000000-0000-4000-a000-000000000001','operator');
 BEGIN
  PERFORM public.aegisops_set_role('00000000-0000-4000-a000-000000000002','viewer'); RAISE EXCEPTION 'Self-demotion allowed';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-a000-000000000001',true);
SELECT set_config('request.jwt.claims','{"sub":"00000000-0000-4000-a000-000000000001","session_id":"00000000-0000-4000-b000-000000000001","role":"authenticated","exp":4102444800}',true);
DO $$ BEGIN
 IF (SELECT role FROM public.aegisops_identity()) <> 'operator' THEN RAISE EXCEPTION 'Role change not fresh'; END IF;
END $$;
RESET ROLE;
DELETE FROM auth.sessions WHERE id='00000000-0000-4000-b000-000000000001';
SET LOCAL ROLE authenticated;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM public.aegisops_identity()) THEN RAISE EXCEPTION 'Signed-out session accepted'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM aegisops_auth.role_changes WHERE target_id='00000000-0000-4000-a000-000000000001' AND old_role='viewer' AND new_role='operator') THEN RAISE EXCEPTION 'Role change not audited'; END IF;
END $$;
SELECT 'PASS: viewer default, metadata spoof rejection, admin checks, fresh role, logout rejection, role audit' AS verification;
ROLLBACK;
