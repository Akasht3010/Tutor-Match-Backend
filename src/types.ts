export type UserType = {
    firstName: string,
    lastName: string,
    email: string,
    phone: number,
    gender: string,
    dob: Date,
    profilePic: string,
    password: string,
};

export type TutorType = {
    firstName: string,
    lastName: string,
    email: string,
    phone: number,
    gender: string,
    dob: Date,
    profilePic: string,
    subjects: string[],
    qualification: string,
    experience: number,
    availability: boolean,
    password: string,
};