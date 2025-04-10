document.getElementById('donationForm').addEventListener('submit', async function (e) {
    e.preventDefault();
  
    const token = localStorage.getItem('token');
    if (!token) {
      alert('You must be logged in!');
      window.location.href = '/';
      return;
    }
  
    const formData = new FormData();
    formData.append('food_name', document.getElementById('food_name').value);
    formData.append('food_description', document.getElementById('food_description').value);
    formData.append('quantity', document.getElementById('quantity').value);
    formData.append('food_image', document.getElementById('food_image').files[0]);
    
    // Assuming donor_id is stored in token payload or separately
    const donorId = localStorage.getItem('user_id'); // Add this in login when saving
    formData.append('donor_id', donorId);
  
    try {
      const response = await fetch('/api/food_donations', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token
        },
        body: formData
      });
  
      const data = await response.json();
  
      if (response.ok) {
        document.getElementById('message').innerHTML = `<div class="alert alert-success">${data.message}</div>`;
        document.getElementById('donationForm').reset();
      } else {
        document.getElementById('message').innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
      }
  
    } catch (error) {
      console.error('Error:', error);
      document.getElementById('message').innerHTML = `<div class="alert alert-danger">Something went wrong.</div>`;
    }
    // If donations table exists, load donations
if (document.getElementById('donationsTable')) {
    loadDonations();
  }
  
  async function loadDonations() {
    try {
      const response = await fetch('/api/food_donations', {
        headers: {
          'Authorization': 'Bearer ' + token
        }
      });
      const donations = await response.json();
  
      const table = document.getElementById('donationsTable');
      table.innerHTML = '';
  
      donations.forEach(donation => {
        const row = `
          <tr>
            <td>${donation.food_name}</td>
            <td>${donation.food_description}</td>
            <td>${donation.quantity}</td>
            <td><img src="/uploads/${donation.food_image}" alt="Food Image" width="100"></td>
            <td>
              ${userType.toLowerCase() === 'recipient' 
                ? `<button class="btn btn-success" onclick="orderFood(${donation.donation_id})">Order</button>`
                : ''}
            </td>
          </tr>
        `;
        table.innerHTML += row;
      });
    } catch (error) {
      console.error('Error loading donations:', error);
    }
  }
  
  async function orderFood(donationId) {
    try {
      const response = await fetch('/api/food_orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({
          donation_id: donationId,
          recipient_id: userId
        })
      });
  
      const data = await response.json();
      if (response.ok) {
        alert('Food ordered successfully!');
        loadDonations();
      } else {
        alert(data.error);
      }
  
    } catch (error) {
      console.error('Error ordering food:', error);
    }
  }
  
  });
  