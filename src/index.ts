import express, { Application } from 'express';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';
import cors from 'cors';

import userRoutes from './Routes/user'

dotenv.config();
const app: Application = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

mongoose.connect(process.env.CLUSTER_URI as string).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.log(err);
})

app.use('/user', userRoutes)

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});