const token = localStorage.getItem('token');

if (!token) {
  alert('Please login first.');
  window.location.href = '/';
}

// Load tracking data
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch('/api/food_orders', {
      headers: {
        'Authorization': 'Bearer ' + token
      }
    });

    const orders = await res.json();
    const table = document.getElementById('trackingTable');
    table.innerHTML = '';

    orders.forEach(order => {
      const row = `
        <tr>
          <td>${order.food_name || 'N/A'}</td>
          <td>${order.donor_id || 'Unknown'}</td>
          <td>${order.recipient_id || 'Unknown'}</td>
          <td>Ordered</td>
          <td>${new Date(order.created_at).toLocaleDateString() || 'N/A'}</td>
        </tr>
      `;
      table.innerHTML += row;
    });
  } catch (err) {
    console.error('Error loading tracking data:', err);
  }
});
