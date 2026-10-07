-- 登録済みPasskey（公開鍵）とユーザーIDの紐付け
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,            -- Credential ID (base64url)
  user_id TEXT NOT NULL,
  display_name TEXT,
  public_key TEXT NOT NULL,       -- COSE公開鍵 (base64url)
  counter INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

-- サーバーが発行したチャレンジ
--   kind = 'reg'  : 端末登録用
--   kind = 'qr'   : 入口QRのトークン（同じQRを複数人が読むので使い回し可）
--   kind = 'auth' : QRを読んだスマホごとに発行する認証用（1回限り）
CREATE TABLE IF NOT EXISTS challenges (
  challenge TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  user_id TEXT,
  display_name TEXT,
  office TEXT,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

-- 勤怠記録（時刻はサーバー時刻）
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  office TEXT NOT NULL,
  at INTEGER NOT NULL,
  credential_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attendance_at ON attendance(at);
