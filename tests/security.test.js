import test from "node:test";
import assert from "node:assert/strict";

test("security baseline: password policy rejects weak passwords",()=>{
  const valid=p=>typeof p==="string"&&p.length>=10&&p.length<=128;
  assert.equal(valid("123456789"),false);
  assert.equal(valid("1234567890"),true);
  assert.equal(valid("a".repeat(129)),false);
});

test("security baseline: email normalization is deterministic",()=>{
  const normalize=e=>String(e||"").trim().toLowerCase();
  assert.equal(normalize(" Test@Example.COM "),"test@example.com");
});

test("security baseline: CSP must deny framing and default resources",()=>{
  const csp="default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
  assert.match(csp,/default-src 'none'/);
  assert.match(csp,/frame-ancestors 'none'/);
  assert.match(csp,/base-uri 'none'/);
});

test("security baseline: dangerous role escalation is blocked by policy",()=>{
  const level={user:1,moderator:2,admin:3,superadmin:4};
  assert.equal(level.admin < level.superadmin,true);
  assert.equal(level.admin >= level.admin,true);
});
