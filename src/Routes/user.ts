import express from 'express'
import { Request, Response } from 'express'
import cookieParser from 'cookie-parser'
import bcrypt from 'bcryptjs'
import jwt, { decode } from 'jsonwebtoken'
import dotenv from 'dotenv'

const router = express.Router()

router.get('/', (req: Request, res: Response) => {
  res.send('Hello World')
})

export default router