const token = localStorage.getItem('token');
if (!token) location.href = '/login.html';

const usersTable = document.getElementById('users');
const status = document.getElementById('status');

// ---------- charger les users ----------
function loadUsers() {
  usersTable.innerHTML = '';
  fetch('/api/admin/users', {
    headers: {
      'Authorization': 'Bearer ' + token
    }
  })
  .then(r => r.json())
  .then(data => {
    data.forEach(u => {
      usersTable.innerHTML += `
        <tr>
          <td>${u.id}</td>
          <td>${u.username}</td>
          <td>${u.balance}</td>
        </tr>
      `;
    });
  });
}

loadUsers();

// ---------- ajouter de l'argent ----------
document.getElementById('addFundsForm').addEventListener('submit', e => {
  e.preventDefault();

  const userId = document.getElementById('userId').value;
  const amount = document.getElementById('amount').value;

  fetch('/api/admin/add-funds', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify({
      userId: Number(userId),
      amount: Number(amount)
    })
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) {
      status.innerText = data.error;
    } else {
      status.innerText = 'Solde mis à jour: ' + data.balance;
      loadUsers(); // ?? RAFRAÎCHIT LA LISTE
    }
  });
});
