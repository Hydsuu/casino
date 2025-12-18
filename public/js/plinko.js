const token = localStorage.getItem('token');
if(!token) location.href='/login.html';

async function loadBalance(){
  const r = await fetch('/api/user/balance',{
    headers:{Authorization:'Bearer '+token}
  });
  const d = await r.json();
  balance.innerText = d.balance;
}
loadBalance();

async function play(){
  error.innerText = '';
  const betValue = Number(bet.value);

  const bal = Number(balance.innerText);
  if(betValue > bal){
    error.innerText = "Solde insuffisant";
    return;
  }

  const res = await fetch('/api/game/plinko/play',{
    method:'POST',
    headers:{
      'Content-Type':'application/json',
      Authorization:'Bearer '+token
    },
    body:JSON.stringify({
      bet: betValue,
      roundId: Date.now()
    })
  });

  const data = await res.json();
  if(!data.success){
    error.innerText = data.error;
    return;
  }

  balance.innerText = data.result.balance_after;
  drawBall();
}

function drawBall(){
  const c = document.getElementById('game');
  const ctx = c.getContext('2d');
  ctx.clearRect(0,0,400,500);

  let y = 0;
  const interval = setInterval(()=>{
    ctx.clearRect(0,0,400,500);
    ctx.beginPath();
    ctx.arc(200, y, 8, 0, Math.PI*2);
    ctx.fill();
    y += 5;
    if(y > 480) clearInterval(interval);
  }, 16);
}
