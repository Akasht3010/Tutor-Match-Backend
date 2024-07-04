import express from 'express'
import { Request, Response } from 'express'
import cookieParser from 'cookie-parser'
import bcrypt from 'bcryptjs'
import jwt, { decode } from 'jsonwebtoken'
import dotenv from 'dotenv'
import multer from 'multer'
import path from 'path'

const router = express.Router()

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '../../uploads'))
  },

  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, uniqueSuffix + path.extname(file.originalname))
  }
})

const uploadMiddleware = multer({ storage })

router.use(cookieParser())

router.get('/', (req: Request, res: Response) => {
  res.send('Hello World')
})

export default router