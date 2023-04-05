const mongoose = require("mongoose");
const Schema = mongoose.Schema
// Validator = require("validatorjs")
const validator = require('validator');

// var uniqueValidator = require("mongoose-unique-validator");

var DeviceInfoSchema = new Schema({

    uuid: {
        type: String,
    },
    token:
    {
        type: String,
    }
});

const AuthSchema = new Schema({
    otp: {
        type: Number,
        default: null
    },
    expire: {
        type: Date,
        default: new Date()
    },
    created: {
        type: Date,
        default: new Date()
    },
});

const AccountInfoSchema = new Schema({
    status: {
        type: String,
        enum: [
            "Active",
            "Deactivate",
            "Deleted",
        ],
        default: "Active",
    },
});

const UserSchema = new Schema({

    name: {
        type: String,
        required: true,
        default: "",
    },

    email: {
        type: String,
        required: true,
        defalut: "",
    },
    password: {
        type: String,
        required: true,
        defalut: "",
    },
    account_info: AccountInfoSchema,
    auth: AuthSchema,
    device: [DeviceInfoSchema],
    logs: [],

},
    { timestamps: true, toJSON: true },
);


UserSchema.set("toObject", { Virtual: true });
UserSchema.set("toJSON", { Virtual: true });
//UserSchema.plugin(uniqueValidator);

const User = mongoose.model("User", UserSchema, "User");
module.exports = User;



