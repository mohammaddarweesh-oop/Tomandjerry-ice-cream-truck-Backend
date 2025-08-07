const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const xss = require("xss");
const compression = require("compression");
const NodeCache = require("node-cache");
const fs = require("fs");
const path = require("path");
const morgan = require("morgan");
const winston = require("winston");
const cron = require("node-cron");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const multer = require("multer");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 4000;
app.use(helmet());
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());
app.use(compression());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    error: "Too many login attempts. Please try again after 15 minutes.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const logDirectory = path.join(__dirname, "logs");
if (!fs.existsSync(logDirectory)) fs.mkdirSync(logDirectory);

const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDirectory, "combined.log"),
    }),
    new winston.transports.File({
      filename: path.join(logDirectory, "errors.log"),
      level: "error",
    }),
  ],
});

app.use(
  morgan("combined", {
    stream: fs.createWriteStream(path.join(logDirectory, "access.log"), {
      flags: "a",
    }),
  })
);
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const cache = new NodeCache({ stdTTL: 300 });

mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));


const uploadDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage,
  fileFilter: function (req, file, cb) {
    const allowedTypes = ["image/jpeg", "image/png", "image/webp"];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only images are allowed"));
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
  },
});


const bookingSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  address: { type: String, required: true },
  city: { type: String, required: true },
  zipCode: { type: String, required: true },
  phone: { type: String, required: true },
  dateTime: { type: Date, required: true }, 
  attendees: { type: Number, required: true, min: 1 },
  duration: { type: Number, required: true, min: 1 }, 
  comments: { type: String, default: "" },
  completed: { type: Boolean, default: false }, 
  createdAt: { type: Date, default: Date.now },
});
const Booking = mongoose.model("Booking", bookingSchema);

const adminSchema = new mongoose.Schema({
  email: String,
  password: String,
});
const Admin = mongoose.model("Admin", adminSchema);

const productSchema = new mongoose.Schema({
  title: String,
  description: String,
  price: Number,
  size: String,
  image: String,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});
const Product = mongoose.model("Product", productSchema);

const contactUsSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});
const ContactUs = mongoose.model("ContactUs", contactUsSchema);

const characterSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: "" },
  image: { type: String, required: true },
});

const Character = mongoose.model("Character", characterSchema);



const bookingValidationSchema = Joi.object({
  name: Joi.string().min(2).required(),
  email: Joi.string().email().required(),
  address: Joi.string().min(3).required(),
  city: Joi.string().min(2).required(),
  zipCode: Joi.string().min(3).required(),
  phone: Joi.string().min(7).max(15).required(),
  dateTime: Joi.date().required(),
  attendees: Joi.number().integer().min(1).required(),
  duration: Joi.number().integer().min(1).required(),
  comments: Joi.string().allow(""),
  completed: Joi.boolean().optional(),
});

const loginValidationSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const productValidationSchema = Joi.object({
  title: Joi.string().min(2).required(),
  description: Joi.string().allow(""),
  price: Joi.number().positive().required(),
  size: Joi.string().required(),
  image: Joi.string().required(),
});

const contactUsValidationSchema = Joi.object({
  name: Joi.string().min(2).required(),
  email: Joi.string().email().required(),
  phone: Joi.string().min(7).max(15).required(),
  message: Joi.string().min(5).required(),
});

const characterValidationSchema = Joi.object({
  name: Joi.string().min(2).required(),
  description: Joi.string().allow(""),
  image: Joi.string().required(),
});


function verifyAdminToken(req, res, next) {
  const token = req.cookies.token;
  if (!token)
    return res.status(401).json({ error: "Access denied. No token provided." });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.adminId = decoded.adminId;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}


app.post("/api/upload", verifyAdminToken, upload.single("image"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }
  const imageUrl = `/uploads/${req.file.filename}`;
  res.status(200).json({ imageUrl });
});

app.get("/api/admin/session", verifyAdminToken, (req, res) => {
  res.status(200).json({ message: "Session is valid", adminId: req.adminId });
});

app.post("/api/admin/login", loginLimiter, async (req, res) => {
  const { error, value } = loginValidationSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const { email, password } = value;
  try {
    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(401).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res
      .cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: (24 * 60 * 60 * 1000) * 90 , 
      })
      .status(200)
      .json({ message: "Login successful" });

    logger.info(`Admin login: ${email} at ${new Date().toISOString()}`);
  } catch (err) {
    logger.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/admin/logout", verifyAdminToken, (req, res) => {
  res.clearCookie("token");
  res.status(200).json({ message: "Logged out successfully" });
});

app.post("/api/booking", async (req, res) => {
  const { error, value } = bookingValidationSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const {
    name,
    email,
    address,
    city,
    zipCode,
    phone,
    dateTime,
    attendees,
    duration,
    comments,
    completed,
  } = value;

  try {
    const sanitizedBooking = {
      name: xss(name),
      email: xss(email),
      address: xss(address),
      city: xss(city),
      zipCode: xss(zipCode),
      phone: xss(phone),
      dateTime: new Date(dateTime),
      attendees,
      duration,
      comments: xss(comments || ""),
      completed: completed || false,
    };

    const newBooking = new Booking(sanitizedBooking);
    await newBooking.save();

    logger.info(
      `New booking by ${sanitizedBooking.email} on ${new Date().toISOString()}`
    );

    res.status(200).json({ message: "Booking request saved successfully!" });
  } catch (err) {
    console.error("Booking error:", err);
    logger.error("Booking error:", err);
    res
      .status(500)
      .json({ error: "Something went wrong. Please try again later." });
  }
});

// GET bookings with pagination and date filtering
app.get("/api/admin/bookings", verifyAdminToken, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;

  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  const filter = {};
  if (startDate && endDate) {
    filter.createdAt = {
      $gte: new Date(startDate),
      $lte: new Date(endDate),
    };
  }

  try {
    const total = await Booking.countDocuments(filter);
    const bookings = await Booking.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    res.status(200).json({ total, page, limit, bookings });
  } catch (err) {
    logger.error("Fetch bookings error:", err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

app.get("/api/admin/bookings/:id", verifyAdminToken, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ error: "Booking not found" });
    res.status(200).json(booking);
  } catch (err) {
    logger.error("Fetch single booking error:", err);
    res.status(500).json({ error: "Failed to fetch booking" });
  }
});


app.put("/api/admin/bookings/:id", verifyAdminToken, async (req, res) => {
  const {
    name,
    email,
    address,
    city,
    zipCode,
    phone,
    dateTime,
    attendees,
    duration,
    comments,
    completed,
  } = req.body;

  if (completed !== undefined && typeof completed !== "boolean") {
    return res.status(400).json({ error: "Invalid 'completed' field" });
  }

  try {
    const updateData = {};
    if (name) updateData.name = xss(name);
    if (email) updateData.email = xss(email);
    if (address) updateData.address = xss(address);
    if (city) updateData.city = xss(city);
    if (zipCode) updateData.zipCode = xss(zipCode);
    if (phone) updateData.phone = xss(phone);
    if (dateTime) updateData.dateTime = new Date(dateTime);
    if (attendees !== undefined) updateData.attendees = attendees;
    if (duration !== undefined) updateData.duration = duration;
    if (comments !== undefined) updateData.comments = xss(comments);
    if (completed !== undefined) updateData.completed = completed;

    const updated = await Booking.findByIdAndUpdate(req.params.id, updateData, {
      new: true,
    });

    if (!updated) return res.status(404).json({ error: "Booking not found" });

    logger.info(`Booking updated by admin: ${req.params.id}`);
    res.status(200).json(updated);
  } catch (err) {
    logger.error("Update booking error:", err);
    res.status(500).json({ error: "Failed to update booking" });
  }
});

// Delete booking by admin
app.delete("/api/admin/bookings/:id", verifyAdminToken, async (req, res) => {
  try {
    const deleted = await Booking.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Booking not found" });
    logger.info(`Booking deleted by admin: ${req.params.id}`);
    res.status(200).json({ message: "Booking deleted successfully" });
  } catch (err) {
    logger.error("Delete booking error:", err);
    res.status(500).json({ error: "Failed to delete booking" });
  }
});

// ================== Contact us ==================

app.post("/api/contactus", async (req, res) => {
  const { error, value } = contactUsValidationSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  try {
    const sanitizedContact = {
      name: xss(value.name),
      email: xss(value.email),
      phone: xss(value.phone),
      message: xss(value.message),
    };

    const newContact = new ContactUs(sanitizedContact);
    await newContact.save();

    logger.info(
      `New contact request by ${
        sanitizedContact.email
      } at ${new Date().toISOString()}`
    );

    res.status(200).json({ message: "Contact request saved successfully!" });
  } catch (err) {
    console.error("Contact us error:", err);
    logger.error("Contact us error:", err);
    res
      .status(500)
      .json({ error: "Something went wrong. Please try again later." });
  }
});

app.get("/api/admin/contactus", verifyAdminToken, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;

  try {
    const total = await ContactUs.countDocuments();
    const contacts = await ContactUs.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    res.status(200).json({ total, page, limit, contacts });
  } catch (err) {
    logger.error("Fetch contact us error:", err);
    res.status(500).json({ error: "Failed to fetch contact messages" });
  }
});

app.delete("/api/admin/contactus/:id", verifyAdminToken, async (req, res) => {
  try {
    const deleted = await ContactUs.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Message not found" });
    logger.info(`Contact message deleted by admin: ${req.params.id}`);
    res.status(200).json({ message: "Message deleted successfully" });
  } catch (err) {
    logger.error("Delete contact message error:", err);
    res.status(500).json({ error: "Failed to delete message" });
  }
});

// ================ End Contact us ================



app.post("/api/products", verifyAdminToken, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Image is required" });
    }

    const { title, description, price, size } = req.body;

    const { error } = productValidationSchema.validate({
      title,
      description,
      price: parseFloat(price),
      size,
      image: `/uploads/${req.file.filename}`, 
    });

    if (error) {
     
      fs.unlinkSync(path.join(uploadDir, req.file.filename));
      return res.status(400).json({ error: error.details[0].message });
    }


    const newProduct = new Product({
      title: xss(title),
      description: xss(description),
      price: parseFloat(price),
      size: xss(size),
      image: `/uploads/${req.file.filename}`,
    });

    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    logger.error("Create product error:", err);
    res.status(500).json({ error: "Failed to create product" });
  }
});


app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.status(200).json(products);
  } catch (err) {
    logger.error("Get products error:", err);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.status(200).json(product);
  } catch (err) {
    logger.error("Get product by ID error:", err);
    res.status(500).json({ error: "Failed to fetch product" });
  }
});

app.get("/api/products", async (req, res) => {
  const { search } = req.query;
  const filter = search ? { title: new RegExp(search, "i") } : {};

  try {
    const products = await Product.find(filter).sort({ createdAt: -1 });
    res.status(200).json(products);
  } catch (err) {
    logger.error("Get products error:", err);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});


app.put("/api/products/:id", verifyAdminToken, upload.single("image"), async (req, res) => {
  try {
    const { title, description, price, size } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : req.body.image;

    const { error, value } = productValidationSchema.validate({
      title,
      description,
      price: parseFloat(price),
      size,
      image: imagePath,
    });

    if (error) {
      if (req.file) fs.unlinkSync(path.join(uploadDir, req.file.filename));
      return res.status(400).json({ error: error.details[0].message });
    }

    const updated = await Product.findByIdAndUpdate(
      req.params.id,
      {
        title: xss(title),
        description: xss(description),
        price: parseFloat(price),
        size: xss(size),
        image: imagePath,
      },
      { new: true }
    );

    if (!updated) return res.status(404).json({ error: "Product not found" });
    res.status(200).json(updated);
  } catch (err) {
    logger.error("Update product error:", err);
    res.status(500).json({ error: "Failed to update product" });
  }
});


app.delete("/api/products/:id", verifyAdminToken, async (req, res) => {
  try {
    const deleted = await Product.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Product not found" });
    res.status(200).json({ message: "Product deleted successfully" });
  } catch (err) {
    logger.error("Delete product error:", err);
    res.status(500).json({ error: "Failed to delete product" });
  }
});

// ===================== characters ===================================

app.post("/api/characters", verifyAdminToken, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Image is required" });
    }

    const { name, description } = req.body;
    const imagePath = `/uploads/${req.file.filename}`;

    const { error } = characterValidationSchema.validate({
      name,
      description,
      image: imagePath,
    });
    if (error) {
      fs.unlinkSync(path.join(uploadDir, req.file.filename));
      return res.status(400).json({ error: error.details[0].message });
    }

    const newCharacter = new Character({
      name: xss(name),
      description: xss(description),
      image: imagePath,
    });

    await newCharacter.save();
    res.status(201).json(newCharacter);
  } catch (err) {
    logger.error("Create character error:", err);
    res.status(500).json({ error: "Failed to create character" });
  }
});

app.get("/api/characters", async (req, res) => {
  try {
    const characters = await Character.find().sort({ createdAt: -1 });
    res.status(200).json(characters);
  } catch (err) {
    logger.error("Get characters error:", err);
    res.status(500).json({ error: "Failed to fetch characters" });
  }
});

app.put("/api/characters/:id", verifyAdminToken, upload.single("image"), async (req, res) => {
  try {
    const { name, description } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : req.body.image;

    const { error } = characterValidationSchema.validate({
      name,
      description,
      image: imagePath,
    });
    if (error) {
      if (req.file) fs.unlinkSync(path.join(uploadDir, req.file.filename));
      return res.status(400).json({ error: error.details[0].message });
    }

    const updated = await Character.findByIdAndUpdate(
      req.params.id,
      {
        name: xss(name),
        description: xss(description),
        image: imagePath,
      },
      { new: true }
    );

    if (!updated) return res.status(404).json({ error: "Character not found" });
    res.status(200).json(updated);
  } catch (err) {
    logger.error("Update character error:", err);
    res.status(500).json({ error: "Failed to update character" });
  }
});

app.delete("/api/characters/:id", verifyAdminToken, async (req, res) => {
  try {
    const character = await Character.findByIdAndDelete(req.params.id);
    if (!character) return res.status(404).json({ error: "Character not found" });

    const imagePath = path.join(__dirname, character.image);
    if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);

    res.status(200).json({ message: "Character deleted successfully" });
  } catch (err) {
    logger.error("Delete character error:", err);
    res.status(500).json({ error: "Failed to delete character" });
  }
});

app.get('/', (req, res) => {
  res.send("Hello from the backend!");
});



// Seeder for admin (run once)
async function seedAdmin() {
  const existing = await Admin.findOne({ email: "admin@icecream.com" });
  if (!existing) {
    const hashedPassword = await bcrypt.hash("admin123", 10);
    await Admin.create({
      email: "admin@icecream.com",
      password: hashedPassword,
    });
    console.log("Admin user created");
  }
}
seedAdmin();

// Cron Job to clean old bookings based on BOOKING_RETENTION_DAYS
cron.schedule("0 0 * * *", async () => {
  const retentionDays = parseInt(process.env.BOOKING_RETENTION_DAYS);
  if (!retentionDays || retentionDays <= 0) {
    logger.info(
      "Booking cleanup disabled (retentionDays set to 0 or not defined)."
    );
    return;
  }

  const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

  try {
    const result = await Booking.deleteMany({ createdAt: { $lt: cutoffDate } });
    logger.info(
      `Cron job: Deleted ${result.deletedCount} bookings older than ${retentionDays} days.`
    );
  } catch (err) {
    logger.error("Cron job error while deleting old bookings:", err);
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
