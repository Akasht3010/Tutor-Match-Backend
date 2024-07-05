import express from 'express'
import { Request, Response } from 'express'
import cookieParser from 'cookie-parser'
import bcrypt from 'bcryptjs'
import jwt, { decode } from 'jsonwebtoken'
import dotenv from 'dotenv'
import multer from 'multer'
import path from 'path'

import UserModel from '../../models/user'

const router = express.Router()
const salt = bcrypt.genSaltSync(10)
const secret = process.env.SECRET_KEY as string

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

router.post('/register', uploadMiddleware.single('profilePic'), async (req: Request, res: Response) => {
  try {
    const file = req.file

    if (!file) {
      res.status(400).json({ message: 'Please upload a file' })
      return
    }

    const { filename } = file
    const profilePic = `uploads/${filename}`

    const { firstName, lastName, email, phone, gender, dob, password } = req.body
    const existingUser = UserModel.findOne({ email })

    if (!existingUser) {
      res.status(400).json({ message: 'User already exists' })
      return
    }

    const hashedPassword = bcrypt.hashSync(password, salt)

    try {
      const newUser = await UserModel.create({
        firstName,
        lastName,
        email,
        phone,
        gender,
        dob,
        profilePic,
        password: hashedPassword
      })

      res.status(201).json({ message: 'User created successfully', user: newUser })
    } catch (err) {
      console.log(err)
    }
  } catch (err) {
    console.log(err)
  }
})

export default router