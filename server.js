const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { sendEmail, sendSMS } = require('./notificationService'); // Keep only one import


const app = express();
const PORT = 3001;
const JWT_SECRET = 'your-secret-key'; // In production, use environment variable
 
app.use(cors({
    origin: 'http://localhost:3000', // Match your frontend's URL
    credentials: true
}));
app.use(bodyParser.json());
 
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const DONATIONS_FILE = path.join(__dirname, 'data', 'donations.json');
const CONTACTS_FILE = path.join(__dirname, 'data', 'contacts.json');
const INDIAN_CAPITAL_CITIES = {
    'New Delhi': ['Delhi', 'New Delhi', 'NCR'],
    'Mumbai': ['Mumbai', 'Bombay'],
    'Bangalore': ['Bangalore', 'Bengaluru'],
    'Chennai': ['Chennai', 'Madras'],
    'Hyderabad': ['Hyderabad', 'Secunderabad'],
    'Kolkata': ['Kolkata', 'Calcutta'],
    'Lucknow': ['Lucknow'],
    'Jaipur': ['Jaipur'],
    'Bhopal': ['Bhopal'],
    'Chandigarh': ['Chandigarh']
  };
// Middleware to verify JWT token
// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        console.error("Authorization token missing");
        return res.status(401).json({ message: 'Authorization required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Token verification error:", err);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        console.log("User authenticated:", user);
        req.user = user;
        next();
    });
};


// Login endpoint
app.post('/login', async (req, res) => {
    const { identifier, password } = req.body;

    try {
        const usersData = await readJsonFile(USERS_FILE);
        const user = usersData.users.find(u =>
            // Check if identifier matches username, email, or phone
            (u.username === identifier || 
             u.email === identifier || 
             u.phone === identifier) && 
            u.password === password
        );

        if (user) {
            const token = jwt.sign(
                { 
                    id: user.id, 
                    username: user.username, 
                    type: user.type,
                    email: user.email,
                    phone: user.phone
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                success: true,
                token,
                userType: user.type,
                username: user.username,
                message: 'Login successful'
            });
        } else {
            res.status(401).json({
                success: false,
                message: 'Invalid credentials. Please check your username/email/phone and password.'
            });
        }
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});
 
// Register endpoint
// Register endpoint
app.post('/register', async (req, res) => {
    const { username, password, email, phone, userType, organization, area } = req.body;

    // Basic validation
    if (!username || !password || !email || !phone) {
        return res.status(400).json({
            success: false,
            message: 'All fields (username, password, email, phone) are required'
        });
    }

    // Basic phone number format validation
    const phoneRegex = /^\d{10}$/;  // Assumes 10-digit phone number
    if (!phoneRegex.test(phone)) {
        return res.status(400).json({
            success: false,
            message: 'Please enter a valid 10-digit phone number'
        });
    }

    try {
        const usersData = await readJsonFile(USERS_FILE);
        
        // Check for existing credentials
        const existingCredentials = [];

        if (usersData.users.some(u => u.username === username)) {
            existingCredentials.push('Username');
        }
        if (usersData.users.some(u => u.email === email)) {
            existingCredentials.push('Email');
        }
        if (usersData.users.some(u => u.phone === phone)) {
            existingCredentials.push('Phone number');
        }

        if (existingCredentials.length > 0) {
            return res.status(400).json({
                success: false,
                message: `${existingCredentials.join(', ')} already registered. Please use different credentials.`
            });
        }

        const newUser = {
            id: (usersData.users.length + 1).toString(),
            username,
            password,
            email,
            phone,
            type: userType,
            createdAt: new Date().toISOString()
        };

        if (userType === 'ngo') {
            newUser.organization = organization;
            newUser.area = area;
        }

        usersData.users.push(newUser);
        await writeJsonFile(USERS_FILE, usersData);

        res.json({
            success: true,
            message: 'Registration successful! Please login.'
        });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});
// Create donation endpoint - Modified to allow both donors and NGOs
// Create donation endpoint
   
   
// Updated donation creation endpoint
// Claim donation endpoint with updated notifications
app.post('/api/donations/:id/claim', authenticateToken, async (req, res) => {
    try {
        const donationsData = await readJsonFile(DONATIONS_FILE);
        const usersData = await readJsonFile(USERS_FILE);
       
        const donationIndex = donationsData.donations.findIndex(d => d.id === req.params.id);
 
        if (donationIndex === -1) {
            return res.status(404).json({
                success: false,
                message: 'Donation not found'
            });
        }
 
        const donation = donationsData.donations[donationIndex];
 
        if (donation.claimed) {
            return res.status(400).json({
                success: false,
                message: 'Donation already claimed'
            });
        }
 
        const claimingUser = usersData.users.find(u => u.id === req.user.id);
       
        // Update donation status
        donationsData.donations[donationIndex] = {
            ...donation,
            claimed: true,
            claimedBy: req.user.id,
            claimedAt: new Date().toISOString()
        };
 
        await writeJsonFile(DONATIONS_FILE, donationsData);
 
        // Send notification to donor
        const emailText = `
Dear ${donation.donorName},
 
Great news! Your donation has been claimed.
 
Donation Details:
- Food Item: ${donation.foodItem}
- Quantity: ${donation.quantity}
- Posted on: ${new Date(donation.createdAt).toLocaleString()}
 
Claimed by:
- Organization: ${claimingUser.organization || claimingUser.username}
- Contact Email: ${claimingUser.email}
- Contact Phone: ${claimingUser.phone}
- Claimed at: ${new Date().toLocaleString()}
 
Thank you for your generous donation and helping make a difference in our community!
 
Best regards,
Food Donation Platform Team
        `;
 
        await sendEmail(
            donation.donorEmail,
            'Your Food Donation Has Been Claimed',
            emailText
        );
 
        // Send SMS if phone number exists
        if (donation.donorPhone) {
            const smsText = `Your donation of ${donation.foodItem} has been claimed by ${claimingUser.organization || claimingUser.username}. Thank you for your contribution!`;
            await sendSMS(donation.donorPhone, smsText);
        }
 
        res.json({
            success: true,
            donation: donationsData.donations[donationIndex]
        });
    } catch (err) {
        console.error('Error claiming donation:', err);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});
// Donations endpoint with comprehensive filtering and functionality
app.get('/api/donations', authenticateToken, async (req, res) => {
    try {
        const donationsData = await readJsonFile(DONATIONS_FILE);
        const usersData = await readJsonFile(USERS_FILE);
        let filteredDonations = donationsData.donations || [];
 
        // 1. Basic View Type Filtering
        const viewType = req.query.view;
       
        if (viewType === 'available') {
            // Show all unclaimed donations
            filteredDonations = filteredDonations.filter(donation => !donation.claimed);
        } else if (viewType === 'my-donations') {
            // Show user's own donations (for donors)
            if (req.user.type === 'donor') {
                filteredDonations = filteredDonations.filter(donation =>
                    donation.donorId === req.user.id
                );
            }
        } else if (viewType === 'claimed') {
            // Show claimed donations (for administrative purposes)
            filteredDonations = filteredDonations.filter(donation => donation.claimed);
        }
 
        // 2. City/Location Filtering
        if (req.query.city) {
            const searchCity = req.query.city.toLowerCase();
            filteredDonations = filteredDonations.filter(donation => {
                if (!donation.area) return false;
               
                // Check if the donation area matches any of our known cities or their variants
                const matchingCity = Object.entries(INDIAN_CAPITAL_CITIES).find(([city, variants]) => {
                    return variants.some(variant =>
                        donation.area.toLowerCase().includes(variant.toLowerCase()) ||
                        variant.toLowerCase().includes(donation.area.toLowerCase())
                    );
                });
 
                if (!matchingCity) return false;
 
                // If we're searching for a specific city, check if it matches
                return matchingCity[0].toLowerCase().includes(searchCity) ||
                       matchingCity[1].some(variant =>
                           variant.toLowerCase().includes(searchCity)
                       );
            });
        }
 
        // 3. Date Filtering
        if (req.query.date) {
            const filterDate = new Date(req.query.date).toDateString();
            filteredDonations = filteredDonations.filter(donation =>
                donation.createdAt &&
                new Date(donation.createdAt).toDateString() === filterDate
            );
        }
 
        // 4. User Type Specific Filtering
        if (req.user.type === 'ngo' && viewType !== 'available') {
            // For NGOs, show donations in their area that they can claim
            const ngoUser = usersData.users.find(user => user.id === req.user.id);
            if (ngoUser && ngoUser.area) {
                filteredDonations = filteredDonations.filter(donation => {
                    const donationArea = donation.area.toLowerCase();
                    const ngoArea = ngoUser.area.toLowerCase();
                   
                    // Check if both areas match any of our known cities
                    const donationCity = Object.entries(INDIAN_CAPITAL_CITIES).find(([_, variants]) =>
                        variants.some(variant => donationArea.includes(variant.toLowerCase()))
                    );
                   
                    const ngoCity = Object.entries(INDIAN_CAPITAL_CITIES).find(([_, variants]) =>
                        variants.some(variant => ngoArea.includes(variant.toLowerCase()))
                    );
                   
                    return !donation.claimed &&
                           donationCity &&
                           ngoCity &&
                           donationCity[0] === ngoCity[0];
                });
            }
        }
 
        // 5. Status Filtering
        if (req.query.status) {
            switch (req.query.status) {
                case 'active':
                    filteredDonations = filteredDonations.filter(d =>
                        !d.claimed && new Date(d.expiryTime) > new Date()
                    );
                    break;
                case 'expired':
                    filteredDonations = filteredDonations.filter(d =>
                        new Date(d.expiryTime) <= new Date()
                    );
                    break;
                case 'claimed':
                    filteredDonations = filteredDonations.filter(d => d.claimed);
                    break;
            }
        }
 
        // 6. Sorting
        const sortBy = req.query.sortBy;
        if (sortBy) {
            switch (sortBy) {
                case 'date':
                    filteredDonations.sort((a, b) =>
                        new Date(b.createdAt) - new Date(a.createdAt)
                    );
                    break;
                case 'expiry':
                    filteredDonations.sort((a, b) =>
                        new Date(a.expiryTime) - new Date(b.expiryTime)
                    );
                    break;
                case 'quantity':
                    filteredDonations.sort((a, b) =>
                        parseInt(b.quantity) - parseInt(a.quantity)
                    );
                    break;
            }
        }
 
        // 7. Enhance donations with additional information
        const enhancedDonations = filteredDonations.map(donation => {
            // Find the standardized city name
            const cityInfo = Object.entries(INDIAN_CAPITAL_CITIES).find(([city, variants]) =>
                variants.some(variant =>
                    donation.area.toLowerCase().includes(variant.toLowerCase())
                )
            );
 
            // Calculate time until expiry
            const timeUntilExpiry = new Date(donation.expiryTime) - new Date();
            const hoursUntilExpiry = Math.floor(timeUntilExpiry / (1000 * 60 * 60));
 
            return {
                ...donation,
                standardizedCity: cityInfo ? cityInfo[0] : donation.area,
                hoursUntilExpiry,
                isExpiringSoon: hoursUntilExpiry <= 24 && hoursUntilExpiry > 0,
                isExpired: hoursUntilExpiry <= 0
            };
        });
 
        // 8. Pagination
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const startIndex = (page - 1) * limit;
        const endIndex = page * limit;
 
        const paginatedDonations = enhancedDonations.slice(startIndex, endIndex);
 
        // 9. Prepare response with metadata
        const response = {
            donations: paginatedDonations,
            metadata: {
                total: enhancedDonations.length,
                page,
                limit,
                totalPages: Math.ceil(enhancedDonations.length / limit),
                hasMore: endIndex < enhancedDonations.length
            }
        };
 
        res.json(response);
 
    } catch (err) {
        console.error('Error fetching donations:', err);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: err.message
        });
    }
});
 
// POST endpoint for creating donations
app.post('/api/donations', authenticateToken, async (req, res) => {
    if (!['donor', 'ngo'].includes(req.user.type)) {
        return res.status(403).json({
            success: false,
            message: 'Only donors and NGOs can create donations'
        });
    }
 
    // Validate required fields
    const requiredFields = ['foodItem', 'quantity', 'location', 'area', 'expiryTime'];
    const missingFields = requiredFields.filter(field => !req.body[field]);
   
    if (missingFields.length > 0) {
        return res.status(400).json({
            success: false,
            message: `Missing required fields: ${missingFields.join(', ')}`
        });
    }
 
    // Validate city/area
    const area = req.body.area?.trim();
    if (!area) {
        return res.status(400).json({
            success: false,
            message: 'Area is required'
        });
    }
 
    // Check if the area matches any known city
    const isValidCity = Object.values(INDIAN_CAPITAL_CITIES).some(variants =>
        variants.some(variant =>
            area.toLowerCase().includes(variant.toLowerCase()) ||
            variant.toLowerCase().includes(area.toLowerCase())
        )
    );
 
    if (!isValidCity) {
        return res.status(400).json({
            success: false,
            message: 'Please provide a valid Indian capital city',
            validCities: Object.keys(INDIAN_CAPITAL_CITIES)
        });
    }
 
    try {
        const donationsData = await readJsonFile(DONATIONS_FILE);
        const usersData = await readJsonFile(USERS_FILE);
 
        // Create new donation object
        const newDonation = {
            id: (donationsData.donations.length + 1).toString(),
            ...req.body,
            donorId: req.user.id,
            donorName: req.user.username,
            donorType: req.user.type,
            donorEmail: req.user.email,
            donorPhone: req.user.phone,
            claimed: false,
            claimedBy: null,
            claimedAt: null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
 
        // Notify nearby NGOs
        const nearbyNgos = usersData.users.filter(user => {
            if (user.type !== 'ngo' || !user.area) return false;
 
            const userArea = user.area.toLowerCase();
            const donationArea = newDonation.area.toLowerCase();
 
            // Check if both areas match any of our known cities
            const donationCity = Object.entries(INDIAN_CAPITAL_CITIES).find(([_, variants]) =>
                variants.some(variant => donationArea.includes(variant.toLowerCase()))
            );
           
            const ngoCity = Object.entries(INDIAN_CAPITAL_CITIES).find(([_, variants]) =>
                variants.some(variant => userArea.includes(variant.toLowerCase()))
            );
           
            return donationCity && ngoCity && donationCity[0] === ngoCity[0];
        });
 
        // Send notifications to nearby NGOs
        for (const ngo of nearbyNgos) {
            const emailText = `
New food donation available in your area!
 
Donation Details:
- Food Item: ${newDonation.foodItem}
- Quantity: ${newDonation.quantity}
- Location: ${newDonation.location}
- Area: ${newDonation.area}
- Best Before: ${new Date(newDonation.expiryTime).toLocaleString()}
- Posted by: ${newDonation.donorName}
 
Additional Information:
${newDonation.dietaryInfo ? `- Dietary Info: ${newDonation.dietaryInfo}` : ''}
${newDonation.storageInstructions ? `- Storage Instructions: ${newDonation.storageInstructions}` : ''}
${newDonation.servingSize ? `- Serving Size: ${newDonation.servingSize}` : ''}
 
Log in to claim this donation.
            `;
 
            try {
                await sendEmail(ngo.email, 'New Food Donation Available', emailText);
            } catch (emailErr) {
                console.error(`Failed to send email to NGO ${ngo.id}:`, emailErr);
            }
        }
 
        // Save the donation
        donationsData.donations.push(newDonation);
        await writeJsonFile(DONATIONS_FILE, donationsData);
 
        res.json({
            success: true,
            message: 'Donation created successfully',
            donation: newDonation,
            notifiedNGOs: nearbyNgos.length
        });
 
    } catch (err) {
        console.error('Error creating donation:', err);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: err.message
        });
    }
});
// Updated NGO directory endpoint
app.get('/api/ngos', authenticateToken, async (req, res) => {
    try {
        const usersData = await readJsonFile(USERS_FILE);
        const ngos = usersData.users
            .filter(user => user.type === 'ngo')
            .map(({ password, ...ngoData }) => ngoData);
       
        res.json(ngos);
    } catch (err) {
        console.error('Error fetching NGO directory:', err);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});
 
 
  // Get statistics
  app.get('/api/stats', async (req, res) => {
    try {
      const [usersData, donationsData] = await Promise.all([
        readJsonFile(USERS_FILE),
        readJsonFile(DONATIONS_FILE)
      ]);
 
      const stats = {
        totalDonors: usersData.users.filter(u => u.type === 'donor').length,
        totalNGOs: usersData.users.filter(u => u.type === 'ngo').length,
        totalDonations: donationsData.donations.length,
        activeDonations: donationsData.donations.filter(d => !d.claimed).length
      };
 
      res.json(stats);
    } catch (err) {
      console.error('Error fetching statistics:', err);
      res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });
 
  // Contact form submission
  app.post('/api/contact', authenticateToken, async (req, res) => {
    try {
      const contactsData = await readJsonFile(CONTACTS_FILE);
      const newContact = {
        id: (contactsData.contacts.length + 1).toString(),
        ...req.body,
        createdAt: new Date().toISOString(),
        responded: false
      };
 
      contactsData.contacts.push(newContact);
      await writeJsonFile(CONTACTS_FILE, contactsData);
 
      res.json({
        success: true,
        message: 'Message sent successfully'
      });
    } catch (err) {
      console.error('Error submitting contact form:', err);
      res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
    
  });

// Add these endpoints to your existing Express server file

// Get Account Settings
app.get('/api/account/settings', authenticateToken, async (req, res) => {
    try {
      const usersData = await readJsonFile(USERS_FILE);
      const user = usersData.users.find(u => u.id === req.user.id);
  
      // Default settings if not exists
      const settings = {
        notifications: user.notifications || true,
        emailUpdates: user.emailUpdates || true,
        privacyMode: user.privacyMode || false
      };
  
      res.json({ 
        success: true, 
        settings 
      });
    } catch (err) {
      console.error('Error fetching account settings:', err);
      res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });
  
  // Update Account Settings
  app.put('/api/account/settings', authenticateToken, async (req, res) => {
    try {
      const usersData = await readJsonFile(USERS_FILE);
      const userIndex = usersData.users.findIndex(u => u.id === req.user.id);
  
      if (userIndex === -1) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
  
      // Update user settings
      usersData.users[userIndex] = {
        ...usersData.users[userIndex],
        notifications: req.body.notifications,
        emailUpdates: req.body.emailUpdates,
        privacyMode: req.body.privacyMode
      };
  
      await writeJsonFile(USERS_FILE, usersData);
  
      res.json({ 
        success: true, 
        message: 'Settings updated successfully' 
      });
    } catch (err) {
      console.error('Error updating account settings:', err);
      res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });
  app.get('/api/donations/my-donations', authenticateToken, async (req, res) => {
  try {
    // Read donations data
    const donationsData = await readJsonFile(DONATIONS_FILE);
    const allDonations = donationsData.donations || [];

    // Filter donations made by the authenticated user
    const userId = req.user.id;
    const userDonations = allDonations.filter(
      (donation) => donation.donorId === userId
    );

    res.status(200).json({
      success: true,
      donations: userDonations,
    });
  } catch (error) {
    console.error('Error fetching user donations:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching donations. Please try again later.',
    });
  }
});
  // Get User Profile
  app.get('/api/account/profile', authenticateToken, async (req, res) => {
    try {
      const usersData = await readJsonFile(USERS_FILE);
      const user = usersData.users.find(u => u.id === req.user.id);
  
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
  
      // Remove sensitive information
      const { password, ...profileData } = user;
  
      res.json({ 
        success: true, 
        profile: profileData 
      });
    } catch (err) {
      console.error('Error fetching user profile:', err);
      res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });
  
  // Update User Profile
  app.put('/api/account/profile', authenticateToken, async (req, res) => {
    try {
      const usersData = await readJsonFile(USERS_FILE);
      const userIndex = usersData.users.findIndex(u => u.id === req.user.id);
  
      if (userIndex === -1) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
  
      // Validate unique credentials
      const { username, email, phone } = req.body;
      const existingUser = usersData.users.find(
        u => u.id !== req.user.id && 
        (u.username === username || u.email === email || u.phone === phone)
      );
  
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Username, email, or phone already in use'
        });
      }
  
      // Update user profile
      usersData.users[userIndex] = {
        ...usersData.users[userIndex],
        ...req.body
      };
  
      await writeJsonFile(USERS_FILE, usersData);
  
      res.json({ 
        success: true, 
        message: 'Profile updated successfully' 
      });
    } catch (err) {
      console.error('Error updating user profile:', err);
      res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });
  app.get('/api/donations/user', authenticateToken, async (req, res) => {
    try {
      // Read the donations.json file
      const donationsData = await readJsonFile(DONATIONS_FILE);
      const allDonations = donationsData.donations || [];
  
      // Filter donations by the logged-in user ID
      const userId = req.user.id; // User ID extracted from the JWT token
      const userDonations = allDonations.filter((donation) => donation.donorId === userId);
  
      res.status(200).json({
        success: true,
        donations: userDonations,
      });
    } catch (error) {
      console.error('Error fetching user donations:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch donations. Please try again later.',
      });
    }
  });

// Helper functions
async function readJsonFile(filePath) {
    const data = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(data);
}
 
async function writeJsonFile(filePath, data) {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
}
 
app.listen(PORT, async () => {
    console.log(`Server is running on port ${PORT}`);
   
});