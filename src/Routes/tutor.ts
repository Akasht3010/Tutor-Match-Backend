import express from 'express'
import { Request, Response } from 'express'
import cookieParser from 'cookie-parser'
import bcrypt from 'bcryptjs'
import jwt, { decode, JwtPayload } from 'jsonwebtoken'
import dotenv from 'dotenv'
import multer from 'multer'
import path from 'path'
import TutorSchema from '../../models/tutor'

const router = express.Router()
const secret = 'bhbiashuasnbibuiuuhvuf9hf0'

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

router.post('/register', async (req: Request, res: Response) => {
  const { firstName, lastName, email, phone, gender, dob, profilePic, subjects, qualification, experience, availability, password } = req.body

  try {
    const existingUser = await TutorSchema.findOne({ email: email });

    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' })
    }

    const hashedPassword = await bcrypt.hash(password, 12)
    const newAdmin = await TutorSchema.create({
      firstName,
      lastName,
      email,
      phone,
      gender,
      dob,
      profilePic,
      subjects,
      qualification,
      experience,
      availability,
      password: hashedPassword
    })

    res.status(201).json({ message: 'User created successfully', data: newAdmin })
  }
  catch (err) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

router.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body

  const isExistingUser = await TutorSchema.findOne({ email: email })

  if (!isExistingUser) {
    return res.status(400).json({ message: 'Invalid credentials' })
  }

  const passOk = bcrypt.compare(password, isExistingUser.password)

  if (!passOk) {
    return res.status(400).json({ message: 'Invalid credentials' })
  }

  const tokenPayload = {
    id: isExistingUser._id,
    firstName: isExistingUser.firstName,
    lastName: isExistingUser.lastName,
    email: isExistingUser.email,
    phone: isExistingUser.phone,
    gender: isExistingUser.gender,
    dob: isExistingUser.dob,
    profilePic: isExistingUser.profilePic,
    subjects: isExistingUser.subjects,
    qualification: isExistingUser.qualification,
    experience: isExistingUser.experience,
    availability: isExistingUser.availability,
    message: 'Login successful'
  }

  try {
    const token = jwt.sign(tokenPayload, secret, { expiresIn: '1h' })
    res.cookie("token", token, { httpOnly: true, secure: true, sameSite: 'none' })
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

router.post('/logout', (req: Request, res: Response) => {
  res.clearCookie('token')
  res.status(200).json({ message: 'Logged out successfully' })
})

router.get('/profile', (req: Request, res: Response) => {
  const { token } = req.cookies.token

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret, (err: any, info: any) => {
    if (err) {
      return res.status(401).json({ message: 'Unauthorized' })
    }
    res.status(200).json(info)
  })
})

router.put('/update-firstName' , async (req : Request, res : Response) => {
  const { firstName } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { firstName }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'First name updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update First Name Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-lastName' , async (req : Request, res : Response) => {
  const { lastName } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { lastName }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Last name updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Last Name Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-email' , async (req : Request, res : Response) => {
  const { email } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { email }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Email updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Email Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-phone' , async (req : Request, res : Response) => {
  const { phone } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { phone }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Phone updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Phone Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-gender' , async (req : Request, res : Response) => {
  const { gender } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { gender }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Phone updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Phone Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-dob' , async (req : Request, res : Response) => {
  const { dob } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { dob }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Date of Birth updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Date of Birth Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-profilePic' , uploadMiddleware.single('profilePic'), async (req : Request, res : Response) => {
  const { profilePic } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { profilePic }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Profile Picture updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Profile Picture Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-subjects' , async (req : Request, res : Response) => {
  const { subjects } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { subjects }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Subjects updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Subjects Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-qualification' , async (req : Request, res : Response) => {
  const { qualification } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { qualification }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Qualification updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Qualification Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-experience' , async (req : Request, res : Response) => {
  const { experience } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { experience }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Experience updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Experience Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.put('/update-availability' , async (req : Request, res : Response) => {
  const { availability } = req.body
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const updateTutor = await TutorSchema.findByIdAndUpdate(info.id, { availability }, { new: true })

      if(!updateTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Availability updated successfully', data: updateTutor })
    } catch{err}{
      console.log('Update Availability Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})

router.delete('/delete', async (req : Request, res : Response) => {
  const { token } = req.cookies.token

  if(!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, secret,{}, async (err: any, decoded: any) => {
    if(err) {
      console.log('JWT Verification Error:', err)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    try {
      const info = decoded as JwtPayload
      const deleteTutor = await TutorSchema.findByIdAndDelete(info.id)

      if(!deleteTutor) {
        return res.status(400).json({ message: 'Tutor not found' })
      }

      return res.status(200).json({ message: 'Tutor deleted successfully', data: deleteTutor })
    } catch{err}{
      console.log('Delete Tutor Error:', err)
      return res.status(500).json({ message: 'Internal server error' })
    }
  })
})


export default router