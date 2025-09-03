const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const app = express();

// Load environment variables
dotenv.config();

// Validate environment variables
if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
  console.error('Error: EMAIL_USER and EMAIL_PASS must be defined in the .env file.');
  process.exit(1); // Exit the process if environment variables are missing
}

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Serve static files from the uploads folder
app.use('/uploads', express.static('uploads'));

// Set up multer storage for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

// Nodemailer setup with explicit SMTP configuration
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // Use TLS
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Verify Nodemailer transporter setup
transporter.verify((error, success) => {
  if (error) {
    console.error('Nodemailer configuration error:', error);
  } else {
    console.log('Nodemailer is ready to send emails');
  }
});

// Function to generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
};

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/userDB')
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("Connection Error: ", err));

// Define OTP Schema and Model
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  otp: { type: String, required: true },
  expires: { type: Date, required: true },
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, expires: 600 } // TTL index: expire after 10 minutes (600 seconds)
});

const Otp = mongoose.model('Otp', otpSchema);

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  favoriteAnimal: { type: String, required: true },
  contactNumber: {
    type: String,
    required: true,
    validate: {
      validator: function (v) {
        return /^\d{10}$/.test(v);
      },
      message: 'Contact number must be exactly 10 digits.',
      

    },
  },
  otp: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Define Job Schema and Model
const jobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  company: { type: String, required: true },
  location: { type: String, required: true },
  salary: { type: Number, required: true },
  vacancies: { type: Number, required: true },
  experience: { type: String, required: true },
  skills: [{ type: String }],
  qualification: { type: String, required: true },
  industryType: { type: String, required: true },
  employmentType: {
    type: String,
    enum: ['Full-time', 'Part-time', 'Contract', 'Internship'],
    required: true
  },
  education: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  logo: { type: String },
  contactEmail: { type: String, required: true },
  updatedAt: { type: Date, default: Date.now },
});

const Job = mongoose.model('Job', jobSchema);

// Define Room Schema and Model
const roomSchema = new mongoose.Schema({
  availability: { type: Boolean, required: true },
  forroom: { type: String, required: true },
  location: { type: String, required: true },
  price: { type: Number, required: true },
  roomType: { type: String, required: true },
  contactNo: { type: String, required: true },
  images: [{ type: String }],
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

const Room = mongoose.model('Room', roomSchema);

// Define Food Schema and Model
const foodSchema = new mongoose.Schema({
  foodname: { type: String },
  shopname: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  address: { type: String, required: true },
  image: [{ type: String }],
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

const Food = mongoose.model('Food', foodSchema);

// Define Update Food Schema for user personal database
const updateFoodSchema = new mongoose.Schema({
  foodId: { type: mongoose.Schema.Types.ObjectId, ref: 'Food', required: true },
  foodname: { type: String },
  shopname: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  address: { type: String, required: true },
  image: [{ type: String }],
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedAt: { type: Date, default: Date.now },
});

// Define Update Room Schema for user personal database
const updateRoomSchema = new mongoose.Schema({
  roomId: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
  roomType: { type: String, required: true },
  price: { type: Number, required: true },
  location: { type: String, required: true },
  contactNo: {
    type: String,
    required: true,
    validate: {
      validator: function (v) {
        return /^\d{10}$/.test(v);
      },
      message: 'Contact number must be exactly 10 digits.',
    },
  },
  forroom: { type: String, required: true },
  availability: { type: Boolean, required: true },
  images: [{ type: String }],
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedAt: { type: Date, default: Date.now },
});

// Define Update Job Schema for user personal database
const updateJobSchema = new mongoose.Schema({
  jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'Job', required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  company: { type: String, required: true },
  location: { type: String, required: true },
  salary: { type: Number, required: true },
  vacancies: { type: Number, required: true },
  experience: { type: String, required: true },
  skills: [{ type: String }],
  qualification: { type: String, required: true },
  industryType: { type: String, required: true },
  employmentType: {
    type: String,
    enum: ['Full-time', 'Part-time', 'Contract', 'Internship'],
    required: true
  },
  education: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  logo: { type: String },
  updatedAt: { type: Date, default: Date.now },
});

// Define SavedJob Schema and Model
const savedJobSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  job: { type: mongoose.Schema.Types.Mixed, required: true },
  savedAt: { type: Date, default: Date.now },
});

const SavedJob = mongoose.model('SavedJob', savedJobSchema);

// Define SavedRoom Schema and Model
const savedRoomSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  room: { type: mongoose.Schema.Types.Mixed, required: true },
  savedAt: { type: Date, default: Date.now },
});

const SavedRoom = mongoose.model('SavedRoom', savedRoomSchema);

// Define SavedFood Schema and Model
const savedFoodSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  food: { type: mongoose.Schema.Types.Mixed, required: true },
  savedAt: { type: Date, default: Date.now },
});

const SavedFood = mongoose.model('SavedFood', savedFoodSchema);

// Add root route
app.get('/', (req, res) => {
  res.status(200).send('Welcome to the User Authentication API!');
});

// Send OTP Endpoint - Save OTP to Database with Detailed Logging
app.post('/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    console.log(`Received /send-otp request with email: ${email}`);
    
    if (!email) {
      console.log('Email is missing in the request');
      return res.status(400).send({ error: 'Email is required' });
    }

    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log(`Email ${email} already exists in the users collection`);
      return res.status(400).send({ error: 'Email already exists' });
    }

    const otp = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry
    console.log(`Generated OTP: ${otp}, Expires at: ${expires}`);

    // Save OTP to database (upsert to ensure only one OTP per email)
    const otpDoc = await Otp.findOneAndUpdate(
      { email },
      { email, otp, expires, verified: false },
      { upsert: true, new: true }
    );
    console.log(`OTP saved to database: ${JSON.stringify(otpDoc)}`);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for Registration',
      text: `Hi, your ClusterView Verification is ${otp}. It is valid for 10 minutes.`,
    };

    // Send email and log detailed response
    await transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending OTP email:', {
          error: error.message,
          code: error.code,
          response: error.response,
          responseCode: error.responseCode,
        });
        return res.status(500).send({ error: 'Failed to send OTP', details: error.message });
      }
      console.log('OTP email sent successfully:', info.response);
      res.status(200).send({ message: 'OTP sent successfully' });
    });
  } catch (error) {
    console.error('Error in /send-otp endpoint:', {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).send({ error: 'Failed to send OTP', details: error.message });
  }
});

// Verify OTP Endpoint - Retrieve OTP from Database
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).send({ error: 'Email and OTP are required' });
    }

    const storedOtp = await Otp.findOne({ email });
    if (!storedOtp) {
      return res.status(400).send({ error: 'OTP not found or expired' });
    }

    if (storedOtp.expires < new Date()) {
      await Otp.deleteOne({ email });
      return res.status(400).send({ error: 'OTP has expired' });
    }

    if (storedOtp.otp !== otp) {
      return res.status(400).send({ error: 'Invalid OTP' });
    }

    // OTP is valid, mark as verified
    storedOtp.verified = true;
    await storedOtp.save();

    res.status(200).send({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).send({ error: 'Failed to verify OTP', details: error.message });
  }
});

// Register Endpoint - Update to Delete OTP After Registration
app.post('/register', async (req, res) => {
  try {
    const { username, email, password, favoriteAnimal, contactNumber } = req.body;
    if (!username || !email || !password || !favoriteAnimal || !contactNumber) {
      return res.status(400).send({ error: 'All fields are required' });
    }

    // Check OTP verification
    const storedOtp = await Otp.findOne({ email });
    if (!storedOtp || !storedOtp.verified) {
      return res.status(400).send({ error: 'OTP verification required' });
    }

    // Create new user with OTP
    const newUser = new User({
      username,
      email,
      password,
      favoriteAnimal,
      contactNumber,
      otp: storedOtp.otp, // Save the OTP in the users collection
    });
    await newUser.save();

    const sanitizedUsername = username.replace(/\s+/g, '_');
    const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    userDb.once('open', async () => {
      console.log(`Database created: ${sanitizedUsername}`);

      const userDetailSchema = new mongoose.Schema({
        username: { type: String, required: true },
        email: { type: String, required: true },
        password: { type: String, required: true },
        favoriteAnimal: { type: String, required: true },
        contactNumber: { type: String, required: true },
        otp: { type: String }, // Add OTP field in personal database
      });

      const UserDetail = userDb.model('user_detail', userDetailSchema);
      const userDetail = new UserDetail({
        username,
        email,
        password,
        favoriteAnimal,
        contactNumber,
        otp: storedOtp.otp, // Save the OTP in the personal database
      });
      await userDetail.save();

      // Delete OTP from database after successful registration
      await Otp.deleteOne({ email });

      res.status(201).send({ message: 'User Registered Successfully' });
    });

    userDb.on('error', (err) => {
      console.error('Error creating user\'s personal database:', err);
      res.status(500).send({ error: 'Database creation failed' });
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).send({ error: 'Email already exists' });
    }
    res.status(500).send({ error: error.message });
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).send({ error: 'Email and Password are required' });
    }

    const user = await User.findOne({ email });
    if (!user || user.password !== password) {
      return res.status(400).send({ error: 'Invalid Email or Password' });
    }

    res.status(200).send({ message: 'Login Successful' });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
  try {
    const { email, favoriteAnimal } = req.body;
    if (!email || !favoriteAnimal) {
      return res.status(400).send({ error: 'Email and favorite animal are required' });
    }

    const user = await User.findOne({ email, favoriteAnimal });
    if (!user) {
      return res.status(400).send({ error: 'No matching user found' });
    }

    res.status(200).send({ password: user.password });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Insert Room Endpoint
app.post('/insert-room', upload.array('images', 10), async (req, res) => {
  try {
    const { roomType, price, location, contactNo, forroom, availability, email, password } = req.body;
    const images = req.files.map(file => file.path);

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const newRoom = new Room({ roomType, price, location, contactNo, forroom, availability, images, userId: user._id });
    await newRoom.save();

    // Save initial data to user's personal database
    const sanitizedUsername = user.username.replace(/\s+/g, '_');
    const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    userDb.once('open', async () => {
      console.log(`Connected to user's personal database: ${sanitizedUsername}`);
      const UpdateRoom = userDb.model('update_room', updateRoomSchema, 'update_room');
      const updateRoom = new UpdateRoom({
        roomId: newRoom._id,
        roomType,
        price,
        location,
        contactNo,
        forroom,
        availability,
        images,
        userId: user._id,
      });
      await updateRoom.save();
    });

    userDb.on('error', (err) => {
      console.error("Error connecting to user's personal database:", err);
    });

    res.status(201).send({ message: "Room Inserted Successfully" });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Insert Food Endpoint
app.post('/insert-food', upload.array('images', 10), async (req, res) => {
  try {
    const { foodname, shopname, description, price, category, address, email, password } = req.body;
    const image = req.files.map(file => file.path);

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const newFood = new Food({ foodname, shopname, description, price, category, address, image, userId: user._id });
    await newFood.save();

    // Save initial data to user's personal database
    const sanitizedUsername = user.username.replace(/\s+/g, '_');
    const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    userDb.once('open', async () => {
      console.log(`Connected to user's personal database: ${sanitizedUsername}`);
      const UpdateFood = userDb.model('update_food', updateFoodSchema, 'update_food');
      const updateFood = new UpdateFood({
        foodId: newFood._id,
        foodname,
        shopname,
        description,
        price,
        category,
        address,
        image,
        userId: user._id,
      });
      await updateFood.save();
    });

    userDb.on('error', (err) => {
      console.error("Error connecting to user's personal database:", err);
    });

    res.status(201).send({ message: "Food Inserted Successfully" });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Insert Job Endpoint
app.post('/insert-job', upload.single('logo'), async (req, res) => {
  try {
    const {
      title, description, company, location, salary,
      vacancies, experience, skills, qualification,
      industryType, employmentType, education,
      contactEmail,
      email, password
    } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const logo = req.file ? req.file.path : null;

    const newJob = new Job({
      title, description, company, location, salary,
      vacancies, experience, skills: skills.split(','),
      qualification, industryType, employmentType, education,
      userId: user._id,
      logo,
      contactEmail
    });
    await newJob.save();

    // Update personal database
    const sanitizedUsername = user.username.replace(/\s+/g, '_');
    const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    userDb.once('open', async () => {
      const UpdateJob = userDb.model('update_job', updateJobSchema);
      const updateJob = new UpdateJob({
        jobId: newJob._id,
        title, description, company, location, salary,
        vacancies, experience, skills: skills.split(','),
        qualification, industryType, employmentType, education,
        userId: user._id,
        logo,
        contactEmail
      });
      await updateJob.save();
    });

    res.status(201).send({ message: "Job Inserted Successfully", job: newJob });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Fetch User Details Endpoint
app.post('/get-user-details', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update User Details Endpoint
app.post('/update-user-details', async (req, res) => {
  const { email, password, username, favoriteAnimal, contactNumber } = req.body;

  // Validate contactNumber
  if (contactNumber && !/^\d{10}$/.test(contactNumber)) {
    return res.status(400).json({ error: 'Contact number must be exactly 10 digits' });
  }

  try {
    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Update fields in the main User collection
    user.username = username || user.username;
    user.favoriteAnimal = favoriteAnimal || user.favoriteAnimal;
    user.contactNumber = contactNumber || user.contactNumber;
    await user.save();

    // Update user's personal database
    const sanitizedUsername = user.username.replace(/\s+/g, '_');
    const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    userDb.once('open', async () => {
      console.log(`Connected to the personal database: ${sanitizedUsername}`);

      const userDetailSchema = new mongoose.Schema({
        username: { type: String, required: true },
        email: { type: String, required: true },
        password: { type: String, required: true },
        favoriteAnimal: { type: String, required: true },
        contactNumber: {
          type: String,
          required: true,
          validate: {
            validator: function (v) {
              return /^\d{10}$/.test(v);
            },
            message: 'Contact number must be exactly 10 digits.',
          },
        },
      });

      const UserDetail = userDb.model('user_detail', userDetailSchema);
      const userDetail = await UserDetail.findOne({ email });
      if (userDetail) {
        userDetail.username = username || userDetail.username;
        userDetail.favoriteAnimal = favoriteAnimal || userDetail.favoriteAnimal;
        userDetail.contactNumber = contactNumber || userDetail.contactNumber;
        await userDetail.save();
      } else {
        const newUserDetail = new UserDetail({
          username: user.username,
          email: user.email,
          password: user.password,
          favoriteAnimal: user.favoriteAnimal,
          contactNumber: user.contactNumber,
        });
        await newUserDetail.save();
      }

      res.json({
        message: 'User details updated successfully in both main and personal database',
        updatedUser: user,
      });
    });

    userDb.on('error', (err) => {
      console.error("Error connecting to user's personal database:", err);
      res.status(500).json({ error: 'Failed to update user in personal database' });
    });
  } catch (error) {
    console.error('Error updating user details:', error);
    res.status(500).json({ error: 'Failed to update profile: ' + error.message });
  }
});

// Fetch Food Endpoint (User-specific)
app.post('/fetch-food', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const foods = await Food.find({ userId: user._id });
    res.status(200).send(foods);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch food data' });
  }
});

// Fetch Rooms Endpoint (User-specific)
app.post('/fetch-rooms', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const rooms = await Room.find({ userId: user._id });
    res.status(200).send(rooms);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch room data' });
  }
});

// Search Room Endpoint (User-specific POST)
app.post('/search-room', async (req, res) => {
  try {
    const { email, password, type, priceRange, location } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const query = {};

    if (location) {
      query.location = { $regex: location, $options: 'i' };
    }

    if (type) {
      query.roomType = type;
    }

    if (priceRange) {
      const [minPrice, maxPrice] = priceRange.split('-').map(Number);
      if (maxPrice) {
        query.price = { $gte: minPrice, $lte: maxPrice };
      } else {
        query.price = { $gte: minPrice };
      }
    }

    const rooms = await Room.find(query);
    res.status(200).send(rooms);
  } catch (error) {
    console.error('Error fetching rooms:', error);
    res.status(500).send({ error: 'Failed to fetch rooms' });
  }
});

// Save Room Endpoint
app.post('/save-room', async (req, res) => {
  try {
    const { userEmail, room } = req.body;

    if (!userEmail || !room) {
      return res.status(400).send({ error: 'User email and room are required' });
    }

    const existingSavedRoom = await SavedRoom.findOne({ userEmail, 'room._id': room._id });
    if (existingSavedRoom) {
      return res.status(400).send({ error: 'Room already saved' });
    }

    const savedRoom = new SavedRoom({ userEmail, room });
    await savedRoom.save();

    res.status(201).send({ message: 'Room saved successfully' });
  } catch (error) {
    console.error('Error saving room:', error);
    res.status(500).send({ error: 'Failed to save room' });
  }
});

// Get Saved Rooms Endpoint
app.get('/get-saved-rooms', async (req, res) => {
  try {
    const { email } = req.query;

    if (!email) {
      return res.status(400).send({ error: 'Email is required' });
    }

    const savedRooms = await SavedRoom.find({ userEmail: email }).sort({ savedAt: -1 });
    res.status(200).send(savedRooms);
  } catch (error) {
    console.error('Error fetching saved rooms:', error);
    res.status(500).send({ error: 'Failed to fetch saved rooms' });
  }
});

// Unsave Room Endpoint
app.delete('/unsave-room', async (req, res) => {
  try {
    const { userEmail, roomId } = req.body;

    if (!userEmail || !roomId) {
      return res.status(400).send({ error: 'User email and room ID are required' });
    }

    const result = await SavedRoom.deleteOne({ userEmail, 'room._id': roomId });
    if (result.deletedCount === 0) {
      return res.status(404).send({ error: 'Room not found or already unsaved' });
    }

    res.status(200).send({ message: 'Room unsaved successfully' });
  } catch (error) {
    console.error('Error unsaving room:', error);
    res.status(500).send({ error: 'Failed to unsave room' });
  }
});

// Search Food Endpoint
app.post('/search-food', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const foods = await Food.find({});
    res.status(200).send(foods);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch food data' });
  }
});

// Save Food Endpoint
app.post('/save-food', async (req, res) => {
  try {
    const { userEmail, food } = req.body;

    if (!userEmail || !food) {
      return res.status(400).send({ error: 'User email and food are required' });
    }

    const existingSavedFood = await SavedFood.findOne({ userEmail, 'food._id': food._id });
    if (existingSavedFood) {
      return res.status(400).send({ error: 'Food already saved' });
    }

    const savedFood = new SavedFood({ userEmail, food });
    await savedFood.save();

    res.status(201).send({ message: 'Food saved successfully' });
  } catch (error) {
    console.error('Error saving food:', error);
    res.status(500).send({ error: 'Failed to save food' });
  }
});

// Get Saved Foods Endpoint
app.get('/get-saved-foods', async (req, res) => {
  try {
    const { email } = req.query;

    if (!email) {
      return res.status(400).send({ error: 'Email is required' });
    }

    const savedFoods = await SavedFood.find({ userEmail: email }).sort({ savedAt: -1 });
    res.status(200).send(savedFoods);
  } catch (error) {
    console.error('Error fetching saved foods:', error);
    res.status(500).send({ error: 'Failed to fetch saved foods' });
  }
});

// Unsave Food Endpoint
app.delete('/unsave-food', async (req, res) => {
  try {
    const { userEmail, foodId } = req.body;

    if (!userEmail || !foodId) {
      return res.status(400).send({ error: 'User email and food ID are required' });
    }

    const result = await SavedFood.deleteOne({ userEmail, 'food._id': foodId });
    if (result.deletedCount === 0) {
      return res.status(404).send({ error: 'Food not found or already unsaved' });
    }

    res.status(200).send({ message: 'Food unsaved successfully' });
  } catch (error) {
    console.error('Error unsaving food:', error);
    res.status(500).send({ error: 'Failed to unsave food' });
  }
});

// Search Job Endpoint (GET)
app.get('/search-job', async (req, res) => {
  try {
    const { query } = req.query;

    const searchQuery = query
      ? {
          $or: [
            { title: { $regex: query, $options: 'i' } },
            { description: { $regex: query, $options: 'i' } },
            { company: { $regex: query, $options: 'i' } },
            { location: { $regex: query, $options: 'i' } },
          ],
        }
      : {};

    const jobs = await Job.find(searchQuery);
    res.status(200).send(jobs);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch job data' });
  }
});

// Search Job Endpoint (POST)
app.post('/search-job', async (req, res) => {
  try {
    const { query, email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const searchQuery = {};
    if (query) {
      searchQuery.$or = [
        { title: { $regex: query, $options: 'i' } },
        { description: { $regex: query, $options: 'i' } },
        { company: { $regex: query, $options: 'i' } },
        { location: { $regex: query, $options: 'i' } },
      ];
    }
    searchQuery.userId = user._id;

    const jobs = await Job.find(searchQuery);
    res.status(200).send(jobs);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch job data' });
  }
});

// Get Saved Jobs Endpoint
app.get('/get-saved-jobs', async (req, res) => {
  try {
    const { email } = req.query;

    if (!email) {
      return res.status(400).send({ error: 'Email is required' });
    }

    const savedJobs = await SavedJob.find({ userEmail: email }).sort({ savedAt: -1 });
    res.status(200).send(savedJobs);
  } catch (error) {
    console.error('Error fetching saved jobs:', error);
    res.status(500).send({ error: 'Failed to fetch saved jobs' });
  }
});

// Save Job Endpoint
app.post('/save-job', async (req, res) => {
  try {
    const { userEmail, job } = req.body;

    if (!userEmail || !job) {
      return res.status(400).send({ error: 'User email and job are required' });
    }

    const existingSavedJob = await SavedJob.findOne({ userEmail, 'job._id': job._id });
    if (existingSavedJob) {
      return res.status(400).send({ error: 'Job already saved' });
    }

    const savedJob = new SavedJob({ userEmail, job });
    await savedJob.save();

    res.status(201).send({ message: 'Job saved successfully' });
  } catch (error) {
    console.error('Error saving job:', error);
    res.status(500).send({ error: 'Failed to save job' });
  }
});

// Unsave Job Endpoint
app.delete('/unsave-job', async (req, res) => {
  try {
    const { userEmail, jobId } = req.body;

    if (!userEmail || !jobId) {
      return res.status(400).send({ error: 'User email and job ID are required' });
    }

    const result = await SavedJob.deleteOne({ userEmail, 'job._id': jobId });
    if (result.deletedCount === 0) {
      return res.status(404).send({ error: 'Job not found or already unsaved' });
    }

    res.status(200).send({ message: 'Job unsaved successfully' });
  } catch (error) {
    console.error('Error unsaving job:', error);
    res.status(500).send({ error: 'Failed to unsave job' });
  }
});

// AdminPanel
const ADMIN_EMAIL = 'Admin@gmail.com';
const ADMIN_PASSWORD = '123';

// Fetch All Rooms Endpoint (for Admin Panel)
app.get('/fetch-all-rooms', async (req, res) => {
  try {
    const { email, password } = req.query;

    if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
      return res.status(401).send({ error: 'Unauthorized: Admin access required' });
    }

    const rooms = await Room.find({});
    res.status(200).send(rooms);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch rooms' });
  }
});

// Fetch All Foods Endpoint (for Admin Panel)
app.get('/fetch-all-foods', async (req, res) => {
  try {
    const { email, password } = req.query;

    if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
      return res.status(401).send({ error: 'Unauthorized: Admin access required' });
    }

    const foods = await Food.find({}).populate('userId', 'username email');
    res.status(200).send(foods);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch foods' });
  }
});

// Fetch All Jobs Endpoint (for Admin Panel)
app.get('/fetch-all-jobs', async (req, res) => {
  try {
    const { email, password } = req.query;

    if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
      return res.status(401).send({ error: 'Unauthorized: Admin access required' });
    }

    const jobs = await Job.find({}).populate('userId', 'username email');
    res.status(200).send(jobs);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch jobs' });
  }
});

// Modify Update Room Endpoint to Allow Admin Access
app.post('/update-room', upload.array('images', 10), async (req, res) => {
  try {
    const { roomId, roomType, price, location, contactNo, forroom, availability, existingImages, email, password } = req.body;
    const newImages = req.files ? req.files.map(file => file.path) : [];

    const isAdmin = email === ADMIN_EMAIL && password === ADMIN_PASSWORD;
    const user = await User.findOne({ email, password });

    if (!isAdmin && !user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const room = await Room.findById(roomId);
    if (!room) {
      return res.status(404).send({ error: 'Room not found' });
    }

    if (!isAdmin && room.userId.toString() !== user._id.toString()) {
      return res.status(403).send({ error: 'You don’t have permission to modify this room' });
    }

    room.roomType = roomType || room.roomType;
    room.price = price || room.price;
    room.location = location || room.location;
    room.contactNo = contactNo || room.contactNo;
    room.forroom = forroom || room.forroom;
    room.availability = availability !== undefined ? availability : room.availability;

    const updatedImages = existingImages
      ? (Array.isArray(existingImages) ? existingImages : [existingImages]).concat(newImages)
      : newImages.length > 0 ? newImages : room.images;
    room.images = updatedImages;

    await room.save();

    if (!isAdmin) {
      const sanitizedUsername = user.username.replace(/\s+/g, '_');
      const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });

      userDb.once('open', async () => {
        const UpdateRoom = userDb.model('update_room', updateRoomSchema, 'update_room');
        await UpdateRoom.findOneAndUpdate(
          { roomId: room._id, userId: user._id },
          {
            roomType: room.roomType,
            price: room.price,
            location: room.location,
            contactNo: room.contactNo,
            forroom: room.forroom,
            availability: room.availability,
            images: updatedImages,
            updatedAt: new Date(),
          },
          { upsert: true, new: true }
        );
      });
    }

    res.status(200).send({ message: 'Room updated successfully', room });
  } catch (error) {
    console.error('Error in /update-room:', error);
    res.status(500).send({ error: error.message });
  }
});

// Modify Update Food Endpoint to Allow Admin Access
app.post('/update-food', upload.array('images', 10), async (req, res) => {
  try {
    const { foodId, foodname, shopname, description, price, category, address, existingImages, email, password } = req.body;
    const newImages = req.files ? req.files.map(file => file.path) : [];

    const isAdmin = email === ADMIN_EMAIL && password === ADMIN_PASSWORD;
    const user = await User.findOne({ email, password });

    if (!isAdmin && !user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const food = await Food.findById(foodId);
    if (!food) {
      return res.status(404).send({ error: 'Food not found' });
    }

    if (!isAdmin && food.userId.toString() !== user._id.toString()) {
      return res.status(403).send({ error: 'You don’t have permission to modify this food item' });
    }

    food.foodname = foodname || food.foodname;
    food.shopname = shopname || food.shopname;
    food.description = description || food.description;
    food.price = price || food.price;
    food.category = category || food.category;
    food.address = address || food.address;

    const updatedImages = existingImages
      ? (Array.isArray(existingImages) ? existingImages : [existingImages]).concat(newImages)
      : newImages.length > 0 ? newImages : food.image;
    food.image = updatedImages;

    await food.save();

    if (!isAdmin) {
      const sanitizedUsername = user.username.replace(/\s+/g, '_');
      const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });

      userDb.once('open', async () => {
        const UpdateFood = userDb.model('update_food', updateFoodSchema, 'update_food');
        await UpdateFood.findOneAndUpdate(
          { foodId: food._id, userId: user._id },
          {
            foodname: food.foodname,
            shopname: food.shopname,
            description: food.description,
            price: food.price,
            category: food.category,
            address: food.address,
            image: updatedImages,
            updatedAt: new Date(),
          },
          { upsert: true, new: true }
        );
      });
    }

    res.status(200).send({ message: 'Food updated successfully', food });
  } catch (error) {
    console.error('Error in /update-food:', error);
    res.status(500).send({ error: error.message });
  }
});

// Modify Update Job Endpoint to Allow Admin Access
app.post('/update-job', upload.single('logo'), async (req, res) => {
  try {
    const {
      jobId, title, description, company, location, salary,
      vacancies, experience, skills, qualification,
      industryType, employmentType, education,
      contactEmail, email, password
    } = req.body;

    const isAdmin = email === ADMIN_EMAIL && password === ADMIN_PASSWORD;
    const user = await User.findOne({ email, password });

    if (!isAdmin && !user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const job = await Job.findById(jobId);
    if (!job) {
      return res.status(404).send({ error: 'Job not found' });
    }

    if (!isAdmin && job.userId.toString() !== user._id.toString()) {
      return res.status(403).send({ error: 'You don’t have permission to modify this job' });
    }

    const logo = req.file ? req.file.path : job.logo;

    job.title = title || job.title;
    job.description = description || job.description;
    job.company = company || job.company;
    job.location = location || job.location;
    job.salary = salary || job.salary;
    job.vacancies = vacancies || job.vacancies;
    job.experience = experience || job.experience;
    job.skills = skills ? skills.split(',') : job.skills;
    job.qualification = qualification || job.qualification;
    job.industryType = industryType || job.industryType;
    job.employmentType = employmentType || job.employmentType;
    job.education = education || job.education;
    job.logo = logo;
    job.contactEmail = contactEmail || job.contactEmail;

    await job.save();

    if (!isAdmin) {
      const sanitizedUsername = user.username.replace(/\s+/g, '_');
      const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });

      userDb.once('open', async () => {
        const UpdateJob = userDb.model('update_job', updateJobSchema);
        await UpdateJob.findOneAndUpdate(
          { jobId: job._id, userId: user._id },
          {
            title: job.title,
            description: job.description,
            company: job.company,
            location: job.location,
            salary: job.salary,
            vacancies: job.vacancies,
            experience: job.experience,
            skills: job.skills,
            qualification: job.qualification,
            industryType: job.industryType,
            employmentType: job.employmentType,
            education: job.education,
            logo: job.logo,
            contactEmail: job.contactEmail,
            updatedAt: new Date(),
          },
          { upsert: true, new: true }
        );
      });
    }

    res.status(200).send({ message: 'Job updated successfully', job });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Modify Delete Room Endpoint to Allow Admin Access
app.post('/delete-room', async (req, res) => {
  try {
    const { roomId, email, password } = req.body;

    const isAdmin = email === ADMIN_EMAIL && password === ADMIN_PASSWORD;
    const user = await User.findOne({ email, password });

    if (!isAdmin && !user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const room = await Room.findById(roomId);
    if (!room) {
      return res.status(404).send({ error: 'Room not found' });
    }

    if (!isAdmin && room.userId.toString() !== user._id.toString()) {
      return res.status(403).send({ error: 'You don’t have permission to delete this room' });
    }

    await Room.deleteOne({ _id: roomId });

    if (!isAdmin) {
      const sanitizedUsername = user.username.replace(/\s+/g, '_');
      const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });

      userDb.once('open', async () => {
        const UpdateRoom = userDb.model('update_room', updateRoomSchema, 'update_room');
        await UpdateRoom.deleteOne({ roomId: roomId, userId: user._id });
      });
    }

    res.status(200).send({ message: 'Room deleted successfully' });
  } catch (error) {
    console.error('Error in /delete-room:', error);
    res.status(500).send({ error: error.message });
  }
});

// Modify Delete Food Endpoint to Allow Admin Access
app.post('/delete-food', async (req, res) => {
  try {
    const { foodId, email, password } = req.body;

    const isAdmin = email === ADMIN_EMAIL && password === ADMIN_PASSWORD;
    const user = await User.findOne({ email, password });

    if (!isAdmin && !user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const food = await Food.findById(foodId);
    if (!food) {
      return res.status(404).send({ error: 'Food not found' });
    }

    if (!isAdmin && food.userId.toString() !== user._id.toString()) {
      return res.status(403).send({ error: 'You don’t have permission to delete this food item' });
    }

    await Food.deleteOne({ _id: foodId });

    if (!isAdmin) {
      const sanitizedUsername = user.username.replace(/\s+/g, '_');
      const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });

      userDb.once('open', async () => {
        const UpdateFood = userDb.model('update_food', updateFoodSchema, 'update_food');
        await UpdateFood.deleteOne({ foodId: foodId, userId: user._id });
      });
    }

    res.status(200).send({ message: 'Food deleted successfully' });
  } catch (error) {
    console.error('Error in /delete-food:', error);
    res.status(500).send({ error: error.message });
  }
});

// Modify Delete Job Endpoint to Allow Admin Access
app.post('/delete-job', async (req, res) => {
  try {
    const { jobId, email, password } = req.body;

    const isAdmin = email === ADMIN_EMAIL && password === ADMIN_PASSWORD;
    const user = await User.findOne({ email, password });

    if (!isAdmin && !user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const job = await Job.findById(jobId);
    if (!job) {
      return res.status(404).send({ error: 'Job not found' });
    }

    if (!isAdmin && job.userId.toString() !== user._id.toString()) {
      return res.status(403).send({ error: 'You don’t have permission to delete this job' });
    }

    await Job.deleteOne({ _id: jobId });

    if (!isAdmin) {
      const sanitizedUsername = user.username.replace(/\s+/g, '_');
      const userDb = mongoose.createConnection(`mongodb://127.0.0.1:27017/${sanitizedUsername}`, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });

      userDb.once('open', async () => {
        const UpdateJob = userDb.model('update_job', updateJobSchema, 'update_job');
        await UpdateJob.deleteOne({ jobId: jobId, userId: user._id });
      });
    }

    res.status(200).send({ message: 'Job deleted successfully' });
  } catch (error) {
    console.error('Error in /delete-job:', error);
    res.status(500).send({ error: error.message });
  }
});

// Fetch All Users Endpoint (for Admin Panel)
app.get('/fetch-all-users', async (req, res) => {
  try {
    const { email, password } = req.query;

    if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
      return res.status(401).send({ error: 'Unauthorized: Admin access required' });
    }

    const users = await User.find({}, 'username email password favoriteAnimal');
    res.status(200).send(users);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch users' });
  }
});


// Fetch All Queries Endpoint (for Admin Panel)
app.get('/fetch-all-queries', async (req, res) => {
  try {
    const { email, password } = req.query;

    if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
      return res.status(401).send({ error: 'Unauthorized: Admin access required' });
    }

    const queries = await Query.find({}).sort({ submittedAt: -1 }); // Sort by submission date (newest first)
    res.status(200).send(queries);
  } catch (error) {
    console.error('Error fetching queries:', error);
    res.status(500).send({ error: 'Failed to fetch queries' });
  }
});


// Define Query Schema and Model
const querySchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  query: { type: String, required: true },
  submittedAt: { type: Date, default: Date.now },
});

const Query = mongoose.model('Query', querySchema);

// Submit Query Endpoint
// Submit Query Endpoint with Email Notification to Admin
app.post('/submit-query', async (req, res) => {
  try {
    const { name, email, query } = req.body;
    if (!name || !email || !query) {
      return res.status(400).send({ error: 'All fields are required' });
    }

    // Save the query to the database
    const newQuery = new Query({ name, email, query });
    await newQuery.save();

    // Send email notification to admin
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: 'Admin@gmail.com', // Admin email
      subject: 'New User Query Submitted',
      text: `A new query has been submitted:\n\nName: ${name}\nEmail: ${email}\nQuery: ${query}\n\nPlease respond to the user at your earliest convenience.`,
    };

    await transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending query notification email to admin:', {
          error: error.message,
          code: error.code,
          response: error.response,
          responseCode: error.responseCode,
        });
        // Don't fail the request if email fails; just log the error
      } else {
        console.log('Query notification email sent to admin:', info.response);
      }
    });

    res.status(201).send({ message: 'Query submitted successfully' });
  } catch (error) {
    console.error('Error submitting query:', error);
    res.status(500).send({ error: 'Failed to submit query', details: error.message });
  }
});

// Start Server
const PORT = 8000;
app.listen(PORT, () => {
  console.log(`Server running on http://127.0.0.1:${PORT}`);
});