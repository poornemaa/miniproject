document.getElementById('addRecipientForm').addEventListener('submit', async (e) => {
    e.preventDefault();
  
    const token = localStorage.getItem('token');
    const user_id = localStorage.getItem('user_id');
  
    if (!token) {
      alert('Please login first.');
      window.location.href = '/';
      return;
    }
  
    const recipientData = {
      user_id,
      organization_name: document.getElementById('organization_name').value,
      contact_person: document.getElementById('contact_person').value,
      email: document.getElementById('email').value,
      phone: document.getElementById('phone').value,
      address: document.getElementById('address').value
    };
  
    try {
      const response = await fetch('/api/recipients', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(recipientData)
      });
  
      const result = await response.json();
      document.getElementById('message').innerHTML = `<div class="alert alert-success">${result.message}</div>`;
      document.getElementById('addRecipientForm').reset();
    } catch (err) {
      console.error(err);
      document.getElementById('message').innerHTML = `<div class="alert alert-danger">Something went wrong.</div>`;
    }
  });
  