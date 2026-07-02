import { sendJson } from "./http.js";

const validRoles = new Set(["security", "developer", "manager"]);

export const writeRoles = new Set(["security", "developer"]);
export const securityRole = new Set(["security"]);

export function role(req) {
  const value = String(req.headers["x-demo-role"] ?? "security");
  return validRoles.has(value) ? value : "security";
}

export function requireRole(req, res, allowed) {
  const current = role(req);
  if (!allowed.has(current)) {
    sendJson(res, 403, { error: "Your current role cannot perform this action." });
    return null;
  }
  return current;
}
