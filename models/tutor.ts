import { Schema, model } from "mongoose";
import type { TutorType } from "../src/types";

const TutorSchema = new Schema({
  firstName: {
    type: String,
    required: true,
    trim: true,
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  phone: {
    type: Number,
    required: true,
    unique: true,
    trim: true,
  },
  gender: {
    type: String,
    required: true,
  },
  dob: {
    type: Date,
    required: true,
  },
  profilePic: {
    type: String,
    required: true,
  },
  subjects: {
    type: [String],
    required: true,
  },
  qualification: {
    type: String,
    required: true,
  },
  experience: {
    type: Number,
    required: true,
  },
  availability: {
    type: Boolean,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const TutorModel = model<TutorType>("Tutor", TutorSchema);

export default TutorModel;