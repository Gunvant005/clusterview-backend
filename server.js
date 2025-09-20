const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const cloudinary = require('cloudinary').v2;
const app = express();

// Load environment variables
dotenv.config();

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Validate environment variables
if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS || !process.env.MONGODB_URI) {
  console.error('Error: EMAIL_USER, EMAIL_PASS, and MONGODB_URI must be defined in the .env file.');
  process.exit(1); // Exit if environment variables are missing
}

// Multer setup for Cloudinary (memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only images are allowed'));
    }
    cb(null, true);
  },
});

// Nodemailer setup
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // Use TLS
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

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

// Connect to MongoDB with retry logic
const connectDB = async (retries = 5) => {
  for (let i = 0; i < retries; i++) {
    try {
      await mongoose.connect(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 30000, // 30s timeout for server selection
        socketTimeoutMS: 45000, // Keep socket alive longer
        bufferCommands: false, // Disable buffering to avoid timeouts
        family: 4, // Use IPv4 only
      });
      console.log('MongoDB Connected successfully');
      return true;
    } catch (error) {
      console.error(`Retry ${i + 1}/${retries} failed:`, error.message);
      if (i === retries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5s before retry
    }
  }
};

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = ['https://clusterview-frontend.vercel.app', 'http://localhost:3000'];
    if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes(origin.replace(/\/$/, ''))) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.use(bodyParser.json());

// API Router for /api prefix
const apiRouter = express.Router();
app.use('/api', apiRouter);

// Define schemas and models
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  otp: { type: String, required: true },
  expires: { type: Date, required: true },
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, expires: 600 }, // TTL index: expire after 10 minutes
});
const Otp = mongoose.model('Otp', otpSchema);

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
    required: true,
  },
  education: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  logo: { type: String }, // Store Cloudinary URL
  contactEmail: { type: String, required: true },
  updatedAt: { type: Date, default: Date.now },
});
const Job = mongoose.model('Job', jobSchema);

const roomSchema = new mongoose.Schema({
  availability: { type: Boolean, required: true },
  forroom: { type: String, required: true },
  location: { type: String, required: true },
  price: { type: Number, required: true },
  roomType: { type: String, required: true },
  contactNo: { type: String, required: true },
  images: [{ type: String }], // Store Cloudinary URLs
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});
const Room = mongoose.model('Room', roomSchema);

const foodSchema = new mongoose.Schema({
  foodname: { type: String },
  shopname: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  address: { type: String, required: true },
  image: [{ type: String }], // Store Cloudinary URLs
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});
const Food = mongoose.model('Food', foodSchema);

const updateFoodSchema = new mongoose.Schema({
  foodId: { type: mongoose.Schema.Types.ObjectId, ref: 'Food', required: true },
  foodname: { type: String },
  shopname: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  address: { type: String, required: true },
  image: [{ type: String }], // Store Cloudinary URLs
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedAt: { type: Date, default: Date.now },
});
const UpdateFood = mongoose.model('UpdateFood', updateFoodSchema);

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
  images: [{ type: String }], // Store Cloudinary URLs
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedAt: { type: Date, default: Date.now },
});
const UpdateRoom = mongoose.model('UpdateRoom', updateRoomSchema);

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
    required: true,
  },
  education: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  logo: { type: String }, // Store Cloudinary URL
  updatedAt: { type: Date, default: Date.now },
});
const UpdateJob = mongoose.model('UpdateJob', updateJobSchema);

const savedJobSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  job: { type: mongoose.Schema.Types.Mixed, required: true },
  savedAt: { type: Date, default: Date.now },
});
const SavedJob = mongoose.model('SavedJob', savedJobSchema);

const savedRoomSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  room: { type: mongoose.Schema.Types.Mixed, required: true },
  savedAt: { type: Date, default: Date.now },
});
const SavedRoom = mongoose.model('SavedRoom', savedRoomSchema);

const savedFoodSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  food: { type: mongoose.Schema.Types.Mixed, required: true },
  savedAt: { type: Date, default: Date.now },
});
const SavedFood = mongoose.model('SavedFood', savedFoodSchema);

const querySchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  query: { type: String, required: true },
  submittedAt: { type: Date, default: Date.now },
});
const Query = mongoose.model('Query', querySchema);

// Admin constants
const ADMIN_EMAIL = 'Admin@gmail.com';
const ADMIN_PASSWORD = '123';

// Routes
apiRouter.get('/', (req, res) => {
  res.status(200).send('Welcome to the User Authentication API!');
});

apiRouter.post('/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).send({ error: 'Email is required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send({ error: 'Email already exists' });
    }

    const otp = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry

    const otpDoc = await Otp.findOneAndUpdate(
      { email },
      { email, otp, expires, verified: false },
      { upsert: true, new: true }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for Registration',
      text: `Hi, your ClusterView Verification is ${otp}. It is valid for 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).send({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error in /send-otp:', error);
    res.status(500).send({ error: 'Failed to send OTP', details: error.message });
  }
});

apiRouter.post('/verify-otp', async (req, res) => {
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

    storedOtp.verified = true;
    await storedOtp.save();

    res.status(200).send({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).send({ error: 'Failed to verify OTP', details: error.message });
  }
});

apiRouter.post('/register', async (req, res) => {
  try {
    const { username, email, password, favoriteAnimal, contactNumber } = req.body;
    if (!username || !email || !password || !favoriteAnimal || !contactNumber) {
      return res.status(400).send({ error: 'All fields are required' });
    }

    const storedOtp = await Otp.findOne({ email });
    if (!storedOtp || !storedOtp.verified) {
      return res.status(400).send({ error: 'OTP verification required' });
    }

    const newUser = new User({
      username,
      email,
      password,
      favoriteAnimal,
      contactNumber,
      otp: storedOtp.otp,
    });
    await newUser.save();

    await Otp.deleteOne({ email });

    res.status(201).send({ message: 'User Registered Successfully' });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).send({ error: 'Email already exists' });
    }
    res.status(500).send({ error: error.message });
  }
});

apiRouter.post('/login', async (req, res) => {
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

apiRouter.post('/forgot-password', async (req, res) => {
  try {
    const { email, favoriteAnimal } = req.body;
    if (!email || !favoriteAnimal) {
      return res.status(400).send({ error: 'Email and favorite animal are required' });
    }

    // Check if connection is ready
    if (mongoose.connection.readyState !== 1) {
      return res.status(500).send({ error: 'Database connection is not available' });
    }

    const user = await User.findOne({ email, favoriteAnimal });
    if (!user) {
      return res.status(400).send({ error: 'No matching user found' });
    }

    res.status(200).send({ password: user.password });
  } catch (error) {
    console.error('Forgot Password Error:', error);
    res.status(500).send({ error: 'Failed to retrieve password', details: error.message });
  }
});

apiRouter.post('/insert-room', upload.array('images', 10), async (req, res) => {
  try {
    const { roomType, price, location, contactNo, forroom, availability, email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const imageUrls = [];
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const result = await cloudinary.uploader.upload(`data:${file.mimetype};base64,${file.buffer.toString('base64')}`, {
          resource_type: 'image',
        });
        imageUrls.push(result.secure_url);
      }
    }

    const newRoom = new Room({
      roomType,
      price,
      location,
      contactNo,
      forroom,
      availability,
      images: imageUrls,
      userId: user._id,
    });
    await newRoom.save();

    const updateRoom = new UpdateRoom({
      roomId: newRoom._id,
      roomType,
      price,
      location,
      contactNo,
      forroom,
      availability,
      images: imageUrls,
      userId: user._id,
    });
    await updateRoom.save();

    res.status(201).send({ message: 'Room Inserted Successfully' });
  } catch (error) {
    console.error('Error in /insert-room:', error);
    res.status(500).send({ error: error.message });
  }
});

apiRouter.post('/insert-food', upload.array('images', 10), async (req, res) => {
  try {
    const { foodname, shopname, description, price, category, address, email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    const imageUrls = [];
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const result = await cloudinary.uploader.upload(`data:${file.mimetype};base64,${file.buffer.toString('base64')}`, {
          resource_type: 'image',
        });
        imageUrls.push(result.secure_url);
      }
    }

    const newFood = new Food({
      foodname,
      shopname,
      description,
      price,
      category,
      address,
      image: imageUrls,
      userId: user._id,
    });
    await newFood.save();

    const updateFood = new UpdateFood({
      foodId: newFood._id,
      foodname,
      shopname,
      description,
      price,
      category,
      address,
      image: imageUrls,
      userId: user._id,
    });
    await updateFood.save();

    res.status(201).send({ message: 'Food Inserted Successfully' });
  } catch (error) {
    console.error('Error in /insert-food:', error);
    res.status(500).send({ error: error.message });
  }
});

apiRouter.post('/insert-job', upload.single('logo'), async (req, res) => {
  try {
    const {
      title, description, company, location, salary,
      vacancies, experience, skills, qualification,
      industryType, employmentType, education,
      contactEmail,
      email, password,
    } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).send({ error: 'Unauthorized: Invalid email or password' });
    }

    let logoUrl = null;
    if (req.file) {
      const result = await cloudinary.uploader.upload(`data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`, {
        resource_type: 'image',
      });
      logoUrl = result.secure_url;
    }

    const newJob = new Job({
      title, description, company, location, salary,
      vacancies, experience, skills: skills ? skills.split(',') : [],
      qualification, industryType, employmentType, education,
      userId: user._id,
      logo: logoUrl,
      contactEmail,
    });
    await newJob.save();

    const updateJob = new UpdateJob({
      jobId: newJob._id,
      title, description, company, location, salary,
      vacancies, experience, skills: skills ? skills.split(',') : [],
      qualification, industryType, employmentType, education,
      userId: user._id,
      logo: logoUrl,
    });
    await updateJob.save();

    res.status(201).send({ message: 'Job Inserted Successfully', job: newJob });
  } catch (error) {
    console.error('Error in /insert-job:', error);
    res.status(500).send({ error: error.message });
  }
});

apiRouter.post('/get-user-details', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

apiRouter.post('/update-user-details', async (req, res) => {
  const { email, password, username, favoriteAnimal, contactNumber } = req.body;

  if (contactNumber && !/^\d{10}$/.test(contactNumber)) {
    return res.status(400).json({ error: 'Contact number must be exactly 10 digits' });
  }

  try {
    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    user.username = username || user.username;
    user.favoriteAnimal = favoriteAnimal || user.favoriteAnimal;
    user.contactNumber = contactNumber || user.contactNumber;
    await user.save();

    res.json({
      message: 'User details updated successfully',
      updatedUser: user,
    });
  } catch (error) {
    console.error('Error updating user details:', error);
    res.status(500).json({ error: 'Failed to update profile: ' + error.message });
  }
});

apiRouter.post('/fetch-food', async (req, res) => {
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

apiRouter.post('/fetch-rooms', async (req, res) => {
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

apiRouter.post('/search-room', async (req, res) => {
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

apiRouter.post('/save-room', async (req, res) => {
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

apiRouter.get('/get-saved-rooms', async (req, res) => {
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

apiRouter.delete('/unsave-room', async (req, res) => {
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

apiRouter.post('/search-food', async (req, res) => {
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

apiRouter.post('/save-food', async (req, res) => {
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

apiRouter.get('/get-saved-foods', async (req, res) => {
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

apiRouter.delete('/unsave-food', async (req, res) => {
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

apiRouter.get('/search-job', async (req, res) => {
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

apiRouter.post('/search-job', async (req, res) => {
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

apiRouter.get('/get-saved-jobs', async (req, res) => {
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

apiRouter.post('/save-job', async (req, res) => {
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

apiRouter.delete('/unsave-job', async (req, res) => {
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

apiRouter.get('/fetch-all-rooms', async (req, res) => {
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

apiRouter.get('/fetch-all-foods', async (req, res) => {
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

apiRouter.get('/fetch-all-jobs', async (req, res) => {
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

apiRouter.post('/update-room', upload.array('images', 10), async (req, res) => {
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

    const updateRoom = await UpdateRoom.findOneAndUpdate(
      { roomId: room._id, userId: isAdmin ? null : user._id },
      {
        roomType: room.roomType,
        price: room.price,
        location: room.location,
        contactNo: room.contactNo,
        forroom: room.forroom,
        availability: room.availability,
        images: room.images,
        updatedAt: new Date(),
      },
      { upsert: true, new: true }
    );

    res.status(200).send({ message: 'Room updated successfully', room });
  } catch (error) {
    console.error('Error in /update-room:', error);
    res.status(500).send({ error: error.message });
  }
});

apiRouter.post('/update-food', upload.array('images', 10), async (req, res) => {
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

    const updateFood = await UpdateFood.findOneAndUpdate(
      { foodId: food._id, userId: isAdmin ? null : user._id },
      {
        foodname: food.foodname,
        shopname: food.shopname,
        description: food.description,
        price: food.price,
        category: food.category,
        address: food.address,
        image: food.image,
        updatedAt: new Date(),
      },
      { upsert: true, new: true }
    );

    res.status(200).send({ message: 'Food updated successfully', food });
  } catch (error) {
    console.error('Error in /update-food:', error);
    res.status(500).send({ error: error.message });
  }
});

apiRouter.post('/update-job', upload.single('logo'), async (req, res) => {
  try {
    const {
      jobId, title, description, company, location, salary,
      vacancies, experience, skills, qualification,
      industryType, employmentType, education,
      contactEmail, email, password,
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

    let logoUrl = req.file
      ? (await cloudinary.uploader.upload(`data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`, {
          resource_type: 'image',
        })).secure_url
      : job.logo;

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
    job.logo = logoUrl;
    job.contactEmail = contactEmail || job.contactEmail;

    await job.save();

    const updateJob = await UpdateJob.findOneAndUpdate(
      { jobId: job._id, userId: isAdmin ? null : user._id },
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

    res.status(200).send({ message: 'Job updated successfully', job });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

apiRouter.post('/delete-room', async (req, res) => {
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
    await UpdateRoom.deleteOne({ roomId: roomId, userId: isAdmin ? null : user._id });

    res.status(200).send({ message: 'Room deleted successfully' });
  } catch (error) {
    console.error('Error in /delete-room:', error);
    res.status(500).send({ error: error.message });
  }
});

apiRouter.post('/delete-food', async (req, res) => {
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
    await UpdateFood.deleteOne({ foodId: foodId, userId: isAdmin ? null : user._id });

    res.status(200).send({ message: 'Food deleted successfully' });
  } catch (error) {
    console.error('Error in /delete-food:', error);
    res.status(500).send({ error: error.message });
  }
});

apiRouter.post('/delete-job', async (req, res) => {
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
    await UpdateJob.deleteOne({ jobId: jobId, userId: isAdmin ? null : user._id });

    res.status(200).send({ message: 'Job deleted successfully' });
  } catch (error) {
    console.error('Error in /delete-job:', error);
    res.status(500).send({ error: error.message });
  }
});

apiRouter.get('/fetch-all-users', async (req, res) => {
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

apiRouter.get('/fetch-all-queries', async (req, res) => {
  try {
    const { email, password } = req.query;

    if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
      return res.status(401).send({ error: 'Unauthorized: Admin access required' });
    }

    const queries = await Query.find({}).sort({ submittedAt: -1 });
    res.status(200).send(queries);
  } catch (error) {
    console.error('Error fetching queries:', error);
    res.status(500).send({ error: 'Failed to fetch queries' });
  }
});

apiRouter.post('/submit-query', async (req, res) => {
  try {
    const { name, email, query } = req.body;
    if (!name || !email || !query) {
      return res.status(400).send({ error: 'All fields are required' });
    }

    const newQuery = new Query({ name, email, query });
    await newQuery.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: 'Admin@gmail.com',
      subject: 'New User Query Submitted',
      text: `A new query has been submitted:\n\nName: ${name}\nEmail: ${email}\nQuery: ${query}\n\nPlease respond to the user at your earliest convenience.`,
    };

    await transporter.sendMail(mailOptions);
    res.status(201).send({ message: 'Query submitted successfully' });
  } catch (error) {
    console.error('Error submitting query:', error);
    res.status(500).send({ error: 'Failed to submit query', details: error.message });
  }
});

// Start Server
const PORT = process.env.PORT || 8000;
connectDB().then((success) => {
  if (success) {
    app.listen(PORT, () => {
      console.log(`Server running on http://127.0.0.1:${PORT}`);
    });
  } else {
    process.exit(1); // Exit if all retries fail
  }
});