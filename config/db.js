// config/db.js
const mongoose = require('mongoose');

const connectDB = async () => {
  // Set mongoose options to suppress deprecation warnings
  mongoose.set('strictQuery', false);
  
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      // Modern connection options (Mongoose 8+)
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      family: 4, // Use IPv4, skip trying IPv6
      // Add these for better connection handling
      retryWrites: true,
      w: 'majority'
    });

    console.log(`MongoDB Connected: ${conn.connection.host}`);
    
    // Connection event listeners for better monitoring
    mongoose.connection.on('connected', () => {
      console.log('Mongoose connected to DB');
    });

    mongoose.connection.on('error', (err) => {
      console.error(`Mongoose connection error: ${err.message}`);
    });

    mongoose.connection.on('disconnected', () => {
      console.log('Mongoose disconnected');
      // Attempt to reconnect after 5 seconds
      setTimeout(connectDB, 5000);
    });

    // Handle application termination
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('MongoDB connection closed through app termination');
      process.exit(0);
    });

  } catch (err) {
    console.error('Database connection error:', {
      message: err.message,
      stack: err.stack,
      name: err.name
    });
    
    // Retry connection after 5 seconds
    console.log('Retrying connection in 5 seconds...');
    setTimeout(connectDB, 5000);
  }
};

module.exports = connectDB;