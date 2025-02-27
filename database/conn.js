import mongoose from "mongoose";

import { MongoMemoryServer } from "mongodb-memory-server";
import ENV from '../config.js'

async function connect(){
    const mongod = await MongoMemoryServer.create();
    const getUri = mongod.getUri();

    mongoose.get('strictQuery', true)
    //const db = await mongoose.connect(getUri);
    const db = await mongoose.connect(ENV.ATLAS_URL);
    console.log("Database Connected")
    return db;
}

export default connect;