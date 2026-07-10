--[[
  SentinelMail Gateway — post-scan event POST to the Go control plane.

  Activates the scan event pipeline: on every scanned message we send
  subject + body + extracted URLs + image attachments (base64) to
  /api/v1/mail/events. The Go side persists the mail event, makes the
  final SentinelMail disposition, and fans deeper scan jobs into Redis.

  TO ACTIVATE: rename this to smg_ingest.lua, rebuild the rspamd image,
  and ensure the env var SMG_INGEST_HMAC_KEY is set on the rspamd
  container. The Go side reads the same value from SMG_INGEST_HMAC_KEY.

  Why this uses coro HTTP: quarantine, tagging, and blacklist dispositions
  must be known before the milter result is returned to Postfix.

  Caps (to keep the POST under the api's 16 MiB body limit):
    - body_text truncated to 16 KiB
    - raw_message_b64 truncated to 8 MiB raw message size
    - urls capped at 50
    - image attachments capped at 5, each capped at 2 MiB
]]--

local rspamd_http   = require "rspamd_http"
local rspamd_util   = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local ucl           = require "ucl"          -- rspamd's bundled JSON encoder
local hmac          = require "rspamd_cryptobox_hash"

local api_url = "http://api:8080/api/v1/mail/events"
local sender_policy_url = "http://api:8080/api/v1/mail/sender-policy"
-- Same env var name as the Go side and the workers. Empty value = snippet
-- no-ops gracefully (safe by default; never blocks mail flow).
local secret  = os.getenv("SMG_INGEST_HMAC_KEY") or ""

local MAX_BODY_BYTES       = 16 * 1024
local MAX_RAW_MESSAGE_BYTES = 8 * 1024 * 1024
local MAX_URLS             = 50
local MAX_IMAGE_ATTACHMENTS = 5
local MAX_IMAGE_SIZE       = 2 * 1024 * 1024
local SUBJECT_TAG          = "Spam?"

local function hex_hmac_sha256(key, body)
  local h = hmac.create_specific_keyed(key, "sha256")
  h:update(body)
  return h:hex()
end

local function tagged_subject(subject)
  subject = tostring(subject or "")
  if subject:match("^%s*[Ss][Pp][Aa][Mm]%?") then
    return subject
  end
  if subject == "" then
    return SUBJECT_TAG
  end
  return SUBJECT_TAG .. " " .. subject
end

local function gather_body(task)
  local out = ""
  local parts = task:get_text_parts() or {}
  for _, p in ipairs(parts) do
    -- Prefer text/plain. Strip HTML otherwise.
    local txt = p:get_content() or ""
    out = out .. tostring(txt)
    if #out >= MAX_BODY_BYTES then break end
  end
  if #out > MAX_BODY_BYTES then
    out = string.sub(out, 1, MAX_BODY_BYTES)
  end
  return out
end

local function gather_urls(task)
  local out = {}
  local urls = task:get_urls(true, true) or {}
  for _, u in ipairs(urls) do
    local s = u:get_text() or ""
    if #s > 0 then
      table.insert(out, s)
      if #out >= MAX_URLS then break end
    end
  end
  return out
end

local function gather_raw_message(task)
  local ok, content = pcall(function() return task:get_content() end)
  if not ok or not content then return "" end
  local raw = tostring(content)
  if #raw == 0 or #raw > MAX_RAW_MESSAGE_BYTES then return "" end
  return rspamd_util.encode_base64(raw, 0)
end

local function gather_header(task, name)
  local ok, value = pcall(function() return task:get_header(name) end)
  if not ok or not value then return "" end
  if type(value) == "table" then value = value[1] or "" end
  value = tostring(value or "")
  if #value > 2048 then value = string.sub(value, 1, 2048) end
  return value
end

local function gather_image_attachments(task)
  local out = {}
  local parts = task:get_parts() or {}
  for _, p in ipairs(parts) do
    if #out >= MAX_IMAGE_ATTACHMENTS then break end
    -- task:get_parts() already returns mime_part objects; calling
    -- :get_mimepart() on them is a nil call in rspamd 4.x (that method
    -- only exists on text_part). Use the mime_part's own :get_type()
    -- which returns the {type, subtype} table directly.
    local raw_type, raw_subtype = p:get_type()
    local mtype, msubtype = raw_type, raw_subtype
    if type(raw_type) == "table" then
      mtype = raw_type.type or raw_type[1] or ""
      msubtype = raw_type.subtype or raw_type[2] or ""
    end
    local ctype = (mtype or "") .. "/" .. (msubtype or "")
    if ctype:sub(1, 6):lower() == "image/" then
      local content = p:get_content()
      if content and #content <= MAX_IMAGE_SIZE then
        table.insert(out, {
          content_type = ctype,
          filename     = (p:get_filename() or "") .. "",
          data_b64     = rspamd_util.encode_base64(content, 0),
          size_bytes   = #content,
        })
      end
    end
  end
  return out
end

local function metric_score(task)
  local score = task:get_metric_score("default")
  if type(score) == "table" then
    score = score[1] or score.score or 0
  end
  return tonumber(score) or 0
end

local function metric_action(task)
  local action = task:get_metric_action("default")
  if type(action) == "table" then
    action = action[1] or action.action or "no action"
  end
  return tostring(action or "no action")
end

local function force_reject_score(task)
  local threshold = tonumber(task:get_metric_threshold("reject")) or 15
  local score = metric_score(task)
  if score <= threshold then
    task:set_metric_score("default", threshold + 10)
  end
end

local function decode_json(body)
  local parser = ucl.parser()
  local ok = parser:parse_string(body or "")
  if not ok then return nil end
  return parser:get_object()
end

local function signed_post_json(task, url, payload, timeout)
  local body = ucl.to_format(payload, 'json-compact', true)
  local sig = hex_hmac_sha256(secret, body)

  local http_err, response = rspamd_http.request({
    task = task,
    url = url,
    method = "POST",
    headers = { ["X-SMG-Signature"] = sig },
    mime_type = "application/json",
    body = body,
    timeout = timeout,
    no_ssl_verify = true,
  })

  if http_err then
    return nil, tostring(http_err)
  end
  local code = tonumber(response and response.code) or 0
  local http_body = (response and (response.content or response.body)) or ""
  if code < 200 or code >= 300 then
    return nil, "api status: " .. tostring(code) .. " body=" .. tostring(http_body or "")
  end
  return decode_json(http_body), nil
end

local function smtp_from(task)
  local from = task:get_from("smtp") or {}
  return (from[1] and from[1].addr) or ""
end

local function smtp_to(task)
  local out = {}
  local to = task:get_recipients("smtp") or {}
  for _, a in ipairs(to) do table.insert(out, a.addr) end
  return out
end

local function gather_symbols(task)
  local symbols = {}
  local all = task:get_symbols_all() or {}
  for _, sym in ipairs(all) do
    local name = sym.name or sym.symbol
    if type(name) == "string" and #name > 0 then
      symbols[name] = {
        score = tonumber(sym.score) or 0,
        group = sym.group or "",
        options = sym.options or {},
      }
    end
  end
  if next(symbols) then return symbols end

  local names = task:get_symbols() or {}
  for k, v in pairs(names) do
    local name = nil
    if type(k) == "string" then
      name = k
    elseif type(v) == "string" then
      name = v
    elseif type(v) == "table" then
      name = v.name or v.symbol
    end
    if type(name) == "string" and #name > 0 then
      symbols[name] = true
    end
  end
  return next(symbols) and symbols or nil
end

local function post_mail_event(task, source)
  if secret == "" then return nil end
  local cached = task:cache_get("smg_mail_event_response")
  if cached then return cached end

  local from = task:get_from("smtp") or {}
  local to   = task:get_recipients("smtp") or {}

  local to_list = {}
  for _, a in ipairs(to) do table.insert(to_list, a.addr) end

  -- Heuristic: if sender's domain matches one of our managed domains and
  -- the client is authenticated, mark as outbound. The Go side does the
  -- actual classification too, this is just a hint.
  local direction = "inbound"
  if task:get_user() then direction = "outbound" end

  local payload = {
    direction         = direction,
    queue_id          = task:get_queue_id() or "",
    message_id        = task:get_message_id() or "",
    from              = (from[1] and from[1].addr) or "",
    from_display_name = (from[1] and from[1].name) or "",
    reply_to          = gather_header(task, "Reply-To"),
    to                = to_list,
    client_ip         = tostring(task:get_from_ip() or ""),
    helo              = task:get_helo() or "",
    subject           = task:get_subject() or "",
    size_bytes        = task:get_size() or 0,
    score             = metric_score(task),
    action            = metric_action(task),
    symbols           = gather_symbols(task),
    body_text         = gather_body(task),
    raw_message_b64   = gather_raw_message(task),
    list_unsubscribe  = gather_header(task, "List-Unsubscribe"),
    list_unsubscribe_post = gather_header(task, "List-Unsubscribe-Post"),
    urls              = gather_urls(task),
    attachments       = gather_image_attachments(task),
  }

  local accepted, err = signed_post_json(task, api_url, payload, 8.0)
  if err then
    rspamd_logger.errx(task, "%s http error: %s", source or "SMG_INGEST", err)
    return nil
  end
  task:cache_set("smg_mail_event_response", accepted or {})

  if accepted and accepted.disposition == "quarantined" then
    task:insert_result("SMG_QUARANTINED", 20.0)
    force_reject_score(task)
    task:set_pre_result("discard", nil, "SentinelMail", 20.0, 1000)
  elseif accepted and accepted.disposition == "rejected" then
    task:insert_result("SMG_REJECTED", 20.0)
    force_reject_score(task)
    task:set_pre_result("reject", "message rejected by SentinelMail policy", "SentinelMail", 20.0, 1000)
  elseif accepted and accepted.disposition == "tagged" then
    task:insert_result("SMG_TAGGED", 0.0)
    task:set_metric_subject(tagged_subject(task:get_subject()))
    task:set_pre_result("rewrite subject", "message tagged by SentinelMail")
  end
  rspamd_logger.infox(task, "%s api accepted", source or "SMG_INGEST")
  return accepted
end

rspamd_config:register_symbol({
  name = "SMG_SENDER_POLICY",
  type = "prefilter",
  flags = "coro",
  priority = 1,
  callback = function(task)
    local ok, err = pcall(function()
      if secret == "" then return end

      local payload = {
        from = smtp_from(task),
        reply_to = gather_header(task, "Reply-To"),
        to = smtp_to(task),
      }
      if (payload.from == "" and payload.reply_to == "") or #payload.to == 0 then return end

      local policy, policy_err = signed_post_json(task, sender_policy_url, payload, 3.0)
      if policy_err then
        rspamd_logger.errx(task, "SMG_SENDER_POLICY http error: %s", policy_err)
        return
      end
      if not policy then return end
      if policy.action == "allow" then
        task:insert_result("SMG_SENDER_ALLOWLIST", -20.0)
      elseif policy.action == "block" then
        local reason = policy.reason or "sender matched blacklist"
        task:insert_result("SMG_SENDER_BLACKLIST", 20.0)
        local accepted = post_mail_event(task, "SMG_SENDER_POLICY_INGEST")
        if not accepted or not accepted.disposition then
          task:set_pre_result("reject", reason)
        end
      end
    end)
    if not ok then
      rspamd_logger.errx(task, "SMG_SENDER_POLICY failed: %s", err)
    end
  end,
})

rspamd_config:register_symbol({
  name = "SMG_INGEST",
  type = "postfilter",
  flags = "coro",
  priority = 10,
  callback = function(task)
    local ok, err = pcall(function()
      post_mail_event(task, "SMG_INGEST")
    end)
    if not ok then
      rspamd_logger.errx(task, "SMG_INGEST failed: %s", err)
    end
  end,
})
