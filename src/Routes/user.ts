import express from 'express'
import { Request, Response } from 'express'
import cookieParser from 'cookie-parser'
import bcrypt from 'bcryptjs'
import jwt, { JwtPayload } from 'jsonwebtoken'
import dotenv from 'dotenv'
import multer from 'multer'
import path from 'path'

import UserModel from '../../models/user'

dotenv.config()

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

interface CustomJwtPayload extends JwtPayload {
  id: string;
}

router.post('/register', uploadMiddleware.single('profilePic'), async (req: Request, res: Response) => {
  try {
    const file = req.file

    if (!file) {
      return res.status(400).json({ message: 'Please upload a file' })
    }

    const { filename } = file
    const profilePic = `uploads/${filename}`

    const { firstName, lastName, email, phone, gender, dob, password } = req.body
    const existingUser = await UserModel.findOne({ email })

    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' })
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

      return res.status(201).json({ message: 'User created successfully', user: newUser })
    } catch (err) {
      console.log(err)
      return res.status(500).json({ message: 'Error creating user' })
    }
  } catch (err) {
    console.log(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

router.post("/login", async (req: Request, res: Response) => {
  const { email, password } = req.body

  const isExistingUser = await UserModel.findOne({ email })

  if (!isExistingUser) {
    return res.status(400).json({ message: "User not found" })
  }

  const passOk = bcrypt.compareSync(password, isExistingUser.password)

  if (!passOk) {
    return res.status(400).json({ message: "Invalid credentials" })
  }

  const tokenPayload = {
    id: isExistingUser._id,
    firstName: isExistingUser.firstName,
    lastName: isExistingUser.lastName,
    gender: isExistingUser.gender,
    email: isExistingUser.email,
    phoneNumber: isExistingUser.phone,
    message: "Admin logged in successfully",
  }

  try {
    const token = jwt.sign(tokenPayload, secret, {})
    res.cookie("token", token, { httpOnly: true, secure: true }).json(tokenPayload)
  } catch (err) {
    res.status(500).json({ message: "Internal server error" })
  }
})

router.get("/profile", (req: Request, res: Response) => {
  const { token } = req.cookies

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" })
  }

  try {
    jwt.verify(token, secret, {}, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Unauthorized" })
      }

      res.json(decoded)
    })
  } catch (err) {
    res.status(500).json({ message: "Internal server error" })
  }
})

router.post("/logout", async (req: Request, res: Response) => {
  res.clearCookie("token").json({ message: "Logged out" });
});

router.put("/update/firstName", async (req: Request, res: Response) => {
  const { firstName } = req.body
  const { token } = req.cookies

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" })
  }

  jwt.verify(token, secret, {}, async (err, decoded) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
      const info = decoded as JwtPayload;
      const updatedAdmin = await UserModel.findByIdAndUpdate(info.id, { firstName }, { new: true });

      if (!updatedAdmin) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      return res.status(200).json({ message: 'First name updated successfully', updatedAdmin });
    } catch (updateError) {
      console.error('Database update error:', updateError);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
})

router.put("/update/lastName", async (req: Request, res: Response) => {
  const { lastName } = req.body;
  const { token } = req.cookies;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" })
  }

  jwt.verify(token, secret, {}, async (err, decoded) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(401).json({ message: "Unauthorized" })
    }

    try {
      const info = decoded as JwtPayload;
      const updatedAdmin = await UserModel.findByIdAndUpdate(info.id, { lastName }, { new: true })

      if (!updatedAdmin) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      return res.status(200).json({ message: 'Last name updated successfully', updatedAdmin });
    } catch (updateError) {
      console.error('Database update error:', updateError);
      return res.status(500).json({ error: 'Internal server error' });
    }
  })
})

router.put("/update/email", async (req: Request, res: Response) => {
  const { email } = req.body;
  const { token } = req.cookies;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" })
  }

  jwt.verify(token, secret, {}, async (err, decoded) => {
    if (err) {
      console.log("JWT Verification error: ", err);
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const info = decoded as JwtPayload;
      const updatedAdmin = await UserModel.findByIdAndUpdate(info.id, { email }, { new: true })

      if (!updatedAdmin) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      return res.status(200).json({ message: 'Email updated successfully', updatedAdmin });
    } catch (updateError) {
      console.error('Database update error:', updateError);
      return res.status(500).json({ error: 'Internal server error' });
    }
  })
})

router.put("/update/phone", async (req: Request, res: Response) => {
  const { phone } = req.body;
  const { token } = req.cookies;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" })
  }

  jwt.verify(token, secret, {}, async (err, decoded) => {
    if (err) {
      console.log("JWT Verification error: ", err);
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const info = decoded as JwtPayload;
      const updatedAdmin = await UserModel.findByIdAndUpdate(info.id, { phone }, { new: true })

      if (!updatedAdmin) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      return res.status(200).json({ message: 'Phone Number updated successfully', updatedAdmin });
    } catch (updateError) {
      console.error('Database update error:', updateError);
      return res.status(500).json({ error: 'Internal server error' });
    }
  })
})

router.put("/update/gender", async (req: Request, res: Response) => {
  const { gender } = req.body;
  const { token } = req.cookies;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" })
  }

  jwt.verify(token, secret, {}, async (err, decoded) => {
    if (err) {
      console.log("JWT Verification error: ", err);
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const info = decoded as JwtPayload;
      const updatedAdmin = await UserModel.findByIdAndUpdate(info.id, { gender }, { new: true })

      if (!updatedAdmin) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      return res.status(200).json({ message: 'Gender updated successfully', updatedAdmin });
    } catch (updateError) {
      console.error('Database update error:', updateError);
      return res.status(500).json({ error: 'Internal server error' });
    }
  })
})

router.put("/update/dob", async (req: Request, res: Response) => {
  const { dob } = req.body;
  const { token } = req.cookies;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" })
  }

  jwt.verify(token, secret, {}, async (err, decoded) => {
    if (err) {
      console.log("JWT Verification error: ", err);
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const info = decoded as JwtPayload;
      const updatedAdmin = await UserModel.findByIdAndUpdate(info.id, { dob }, { new: true })

      if (!updatedAdmin) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      return res.status(200).json({ message: 'Date of Birth updated successfully', updatedAdmin });
    } catch (updateError) {
      console.error('Database update error:', updateError);
      return res.status(500).json({ error: 'Internal server error' });
    }
  })
})

router.put("/update/profilePic", uploadMiddleware.single('profilePic'), async (req: Request, res: Response) => {
  const { token } = req.cookies;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" })
  }

  jwt.verify(token, secret, {}, async (err, decoded) => {
    if (err) {
      console.log("JWT Verification error: ", err);
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const info = decoded as JwtPayload;
      const file = req.file

      if (!file) {
        return res.status(400).json({ message: 'Please upload a file' })
      }

      const { filename } = file
      const profilePic = `uploads/${filename}`

      const updatedAdmin = await UserModel.findByIdAndUpdate(info.id, { profilePic }, { new: true })

      if (!updatedAdmin) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      return res.status(200).json({ message: 'Profile Picture updated successfully', updatedAdmin });
    } catch (updateError) {
      console.error('Database update error:', updateError);
      return res.status(500).json({ error: 'Internal server error' });
    }
  })
})

router.put("/update/password", async (req: Request, res: Response) => {
  const { oldPassword, newPassword } = req.body;
  const { token } = req.cookies;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, secret, {}, async (err, decoded) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
      const info = decoded as JwtPayload;
      const admin = await UserModel.findById(info.id);

      if (!admin) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      // Verify the old password before updating
      const isOldPasswordValid = bcrypt.compareSync(oldPassword, admin.password);
      if (!isOldPasswordValid) {
        return res.status(400).json({ error: 'Invalid old password' });
      }

      const hashedPassword = bcrypt.hashSync(newPassword, salt);
      admin.password = hashedPassword;

      await admin.save(); // Use save to update the document

      return res.status(200).json({ message: 'Password updated successfully' });
    } catch (updateError) {
      console.error('Database update error:', updateError);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
});

router.delete("/delete", async (req: Request, res: Response) => {
  const { token } = req.cookies;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, secret, {}, async (err, decoded) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
      const info = decoded as JwtPayload;
      const deletedAdmin = await UserModel.findByIdAndDelete(info.id);

      if (!deletedAdmin) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      return res.status(200).json({ message: 'Admin deleted successfully' });
    } catch (deleteError) {
      console.error('Database delete error:', deleteError);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
});

export default router