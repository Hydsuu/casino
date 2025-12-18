// public/js/balance.js
import { getToken } from "./auth.js";

export async function loadBalance() {
  const res = await fetch("/api/user/balance", {
    headers: {
      "Authorization": "Bearer " + getToken()
    }
  });

  if (!res.ok) return 0;
  const data = await res.json();
  return data.balance;
}
