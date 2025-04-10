// Load orders if on orders page
document.addEventListener('DOMContentLoaded', loadOrders);

async function loadOrders() {
  const token = localStorage.getItem('token');
  if (!token) {
    alert('You must be logged in!');
    window.location.href = '/';
    return;
  }

  try {
    const response = await fetch('/api/food_orders', {
      headers: {
        'Authorization': 'Bearer ' + token
      }
    });

    const orders = await response.json();
    const table = document.getElementById('ordersTable');
    table.innerHTML = '';

    orders.forEach(order => {
      const row = `
        <tr>
          <td>${order.order_id}</td>
          <td>${order.donation_id}</td>
          <td>${order.recipient_id}</td>
        </tr>
      `;
      table.innerHTML += row;
    });

  } catch (error) {
    console.error('Error loading orders:', error);
  }
}
