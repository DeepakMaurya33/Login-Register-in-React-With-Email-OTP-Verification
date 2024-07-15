import toast from "react-hot-toast"
import { authenticate } from './helper'

export async function usernameValidate(values){
    const errors = usernameVerify({}, values);
    
    if(values.username){
        const { status } = await authenticate(values.username);
        if(status !== 200){
            errors.exist = toast.error('User dose not exist...!')
        }
    }
    return errors;
}

export async function passwordValidate(values){
    const errors = passwordVerify({}, values);

    return errors;
}

export async function resetPasswordValidate(values){
    const errors = passwordVerify({}, values);

    if(values.password !== values.confirm_pwd){
        errors.exist = toast.error("Password not match...!");
    }

    return errors;
}

export async function registerValidation(values){
    const errors = usernameVerify({}, values);
    passwordVerify(errors, values);
    emailVerify(errors, values)

    return errors;
}

export const profileValidation = values => {
    const errors = {};

    if (!values.firstName) {
        errors.firstName = 'First Name is required';
    }
    
    if (!values.lastName) {
        errors.lastName = 'Last Name is required';
    }
    
    if (!values.email) {
        errors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(values.email)) {
        errors.email = 'Email address is invalid';
    }
    
    if (!values.mobile) {
        errors.mobile = 'Mobile number is required';
    } else if (!/^\d{10}$/.test(values.mobile)) {
        errors.mobile = 'Mobile number is invalid';
    }

    if (!values.address) {
        errors.address = 'Address is required';
    }

    return errors;
};


function passwordVerify(errors = {}, values){

    const specialChars = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]+/;


    if(!values.password){
        errors.password = toast.error("Password Required...!");
    } else if(values.password.includes(" ")){
        errors.password = toast.error("Wrong Password...!");
    }else if(values.password.length < 4){
        errors.password = toast.error("Password must be more than 4 characters long");
    }else if(!specialChars.test(values.password)){
        errors.password = toast.error("Password must special character");
    }

    return errors;
}


function usernameVerify(error = {}, values){
    if(!values.username){
        error.username = toast.error("Username Required...!");
    }else if(values.username.includes(" ")){
        error.username = toast.error("Invalid Username...!");
    }

    return error;
}

function emailVerify(error ={}, values){
    if(!values.email){
        error.email = toast.error("Email Required...!");
        } else if (values.email.includes(" ")){
            error.email = toast.error("Wrong Email...!");
        } else if( /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]$/i.test(values.email)){
            error.email = toast.error("Invalid email address...!")
        }
        
        return error;
}