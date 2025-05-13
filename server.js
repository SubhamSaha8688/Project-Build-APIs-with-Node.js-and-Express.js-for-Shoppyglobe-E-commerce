// Import required packages
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'shoppyglobe-jwt-secret';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});
app.use(apiLimiter);

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/shoppyglobe')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define Schemas
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const productSchema = new mongoose.Schema({
  id: {
    type: Number,
    required: true,
    unique: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true
  },
  price: {
    type: Number,
    required: true,
    min: 0
  },
  rating: {
    type: Number,
    required: true,
    min: 0,
    max: 5
  },
  stock: {
    type: Number,
    required: true,
    min: 0
  }
});

const cartItemSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  product: {
    type: Number,
    ref: 'Product',
    required: true
  },
  quantity: {
    type: Number,
    required: true,
    min: 1
  },
  addedAt: {
    type: Date,
    default: Date.now
  }
});

// Define Models
const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const CartItem = mongoose.model('CartItem', cartItemSchema);

// Authentication Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'No token, authorization denied' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    res.status(401).json({ error: 'Token is invalid' });
  }
};

// Input Validation Middleware
const validateRegistration = (req, res, next) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Please provide username, email and password' });
  }
  
  if (username.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters long' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long' });
  }
  
  const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Please provide a valid email address' });
  }
  
  next();
};

const validateLogin = (req, res, next) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Please provide email and password' });
  }
  
  next();
};

const validateProductId = async (req, res, next) => {
  const { id } = req.params;
  
  if (!Number.isInteger(parseInt(id))) {
    return res.status(400).json({ error: 'Invalid product ID' });
  }
  
  try {
    const product = await Product.findOne({ id: parseInt(id) });
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    req.product = product;
    next();
  } catch (error) {
    console.error('Product validation error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
};

const validateCartItem = async (req, res, next) => {
  const { productId, quantity } = req.body;
  
  if (!productId || !quantity) {
    return res.status(400).json({ error: 'Product ID and quantity are required' });
  }
  
  if (!Number.isInteger(parseInt(productId))) {
    return res.status(400).json({ error: 'Invalid product ID' });
  }
  
  if (quantity < 1) {
    return res.status(400).json({ error: 'Quantity must be at least 1' });
  }
  
  try {
    const product = await Product.findOne({ id: parseInt(productId) });
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    if (product.stock < quantity) {
      return res.status(400).json({ error: 'Not enough stock available' });
    }
    
    req.product = product;
    next();
  } catch (error) {
    console.error('Cart validation error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
};

// Authentication Routes
app.post('/register', validateRegistration, async (req, res) => {
  const { username, email, password } = req.body;
  
  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }
    
    user = await User.findOne({ username });
    if (user) {
      return res.status(400).json({ error: 'Username is already taken' });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', validateLogin, async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Product Routes
app.get('/products', async (req, res) => {
  try {
    const products = await Product.find().select('-__v');
    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/products/:id', validateProductId, async (req, res) => {
  res.json(req.product);
});

app.post('/products', async (req, res) => {
  const { title, description, category, price, rating, stock } = req.body;
  
  try {
    const lastProduct = await Product.findOne().sort('-id');
    const newId = lastProduct ? lastProduct.id + 1 : 1;

    const newProduct = new Product({
      id: newId,
      title,
      description,
      category,
      price,
      rating,
      stock
    });
    
    const savedProduct = await newProduct.save();
    res.status(201).json(savedProduct);
  } catch (error) {
    console.error('Error creating product:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Cart Routes
app.get('/cart', authenticate, async (req, res) => {
  try {
    const cartItems = await CartItem.find({ user: req.user._id });
    const populatedItems = await Promise.all(
      cartItems.map(async (item) => {
        const product = await Product.findOne({ id: item.product });
        return {
          ...item.toObject(),
          product
        };
      })
    );
    
    res.json(populatedItems);
  } catch (error) {
    console.error('Error fetching cart:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/cart', authenticate, validateCartItem, async (req, res) => {
  const { productId, quantity } = req.body;
  
  try {
    let cartItem = await CartItem.findOne({
      user: req.user._id,
      product: productId
    });
    
    if (cartItem) {
      cartItem.quantity += quantity;
      await cartItem.save();
    } else {
      cartItem = new CartItem({
        user: req.user._id,
        product: productId,
        quantity
      });
      await cartItem.save();
    }
    
    const product = await Product.findOne({ id: productId });
    
    res.status(201).json({
      message: 'Product added to cart',
      cartItem: {
        ...cartItem.toObject(),
        product
      }
    });
  } catch (error) {
    console.error('Error adding to cart:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/cart/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  
  if (!quantity || quantity < 1) {
    return res.status(400).json({ error: 'Quantity must be at least 1' });
  }
  
  try {
    let cartItem = await CartItem.findById(id);
    
    if (!cartItem) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    
    if (cartItem.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to update this cart item' });
    }
    
    const product = await Product.findOne({ id: cartItem.product });
    if (product.stock < quantity) {
      return res.status(400).json({ error: 'Not enough stock available' });
    }
    
    cartItem.quantity = quantity;
    await cartItem.save();
    
    res.json({
      message: 'Cart item updated',
      cartItem: {
        ...cartItem.toObject(),
        product
      }
    });
  } catch (error) {
    console.error('Error updating cart:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/cart/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  
  try {
    const cartItem = await CartItem.findById(id);
    
    if (!cartItem) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    
    if (cartItem.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to delete this cart item' });
    }
    
    await cartItem.deleteOne();
    
    res.json({ message: 'Item removed from cart' });
  } catch (error) {
    console.error('Error removing from cart:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;