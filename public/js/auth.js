// public/js/auth.js
export function getToken() {
  return localStorage.getItem("token");
}

export function requireAuth() {
  const token = getToken();
  if (!token) {
    window.location.href = "/login.html";
  }
}
