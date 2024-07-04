export type UserType = {
    firstName: String,
    lastName: String,
    email: String,
    phone: Number,
    gender: String,
    dob: Date,
    profilePic: String,
    password: String,
};

export type TutorType = {
    firstName: String,
    lastName: String,
    email: String,
    phone: Number,
    gender: String,
    password: String,
    dob: Date,
    profilePic: String,
    subjects: String[],
    qualification: String,
    experience: Number,
    availability: String,
};