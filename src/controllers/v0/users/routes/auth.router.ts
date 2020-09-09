import {Router, Request, Response} from 'express';
import { v4 as uuid } from 'uuid'

import {User} from '../models/User';
import * as c from '../../../../config/config';

import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import {NextFunction} from 'connect';

import * as EmailValidator from 'email-validator';

const router: Router = Router();


async function generatePassword(plainTextPassword: string): Promise<string> {
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);
  return await bcrypt.hash(plainTextPassword, salt);
}

async function comparePasswords(plainTextPassword: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(plainTextPassword, hash);
}

function generateJWT(user: User): string {
  return jwt.sign(user.short(), c.config.jwt.secret);
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  let pid = uuid();
  console.log(new Date().toLocaleString() + `: ${pid} - Requested for User Verification : ${req.body.email}`);
  
  if (!req.headers || !req.headers.authorization) {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for request verification(No authorization headers.) : ${req.body.email}`);
    return res.status(401).send({message: 'No authorization headers.'});
  }

  const tokenBearer = req.headers.authorization.split(' ');
  if (tokenBearer.length != 2) {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for request verification(Malformed token.) : ${req.body.email}`);
    return res.status(401).send({message: 'Malformed token.'});
  }

  const token = tokenBearer[1];
  return jwt.verify(token, c.config.jwt.secret, (err, decoded) => {
    if (err) {
      console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for request verification(Failed to authenticate.) : ${req.body.email}`);
      return res.status(500).send({auth: false, message: 'Failed to authenticate.'});
    }
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for request verification : ${req.body.email}`);
    return next();
  });
}

router.get('/verification',
    requireAuth,
    async (req: Request, res: Response) => {
      return res.status(200).send({auth: true, message: 'Authenticated.'});
    });

router.post('/login', async (req: Request, res: Response) => {
  const email = req.body.email;
  const password = req.body.password;
  let pid = uuid();
  console.log(new Date().toLocaleString() + `: ${pid} - Requested for User Login : ${email}`);
  if (!email || !EmailValidator.validate(email)) {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for User Login(Email is required or malformed.) : ${email}`);
    return res.status(400).send({auth: false, message: 'Email is required or malformed.'});
  }

  if (!password) {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for User Login(Password is required.) : ${email}`);
    return res.status(400).send({auth: false, message: 'Password is required.'});
  }

  const user = await User.findByPk(email);
  if (!user) {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for User Login(User was not found.) : ${email}`);
    return res.status(401).send({auth: false, message: 'User was not found.'});
  }

  const authValid = await comparePasswords(password, user.passwordHash);

  if (!authValid) {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for User Login(Password was invalid.) : ${email}`);
    return res.status(401).send({auth: false, message: 'Password was invalid.'});
  }

  const jwt = generateJWT(user);
  console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for User Login : ${email}`);
  res.status(200).send({auth: true, token: jwt, user: user.short()});
});


router.post('/', async (req: Request, res: Response) => {
  const email = req.body.email;
  const plainTextPassword = req.body.password;
  let pid = uuid();
  console.log(new Date().toLocaleString() + `: ${pid} - Requested for User Register : ${email}`);
  
  if (!email || !EmailValidator.validate(email)) {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for User Register(Email is missing or malformed.) : ${email}`);
    return res.status(400).send({auth: false, message: 'Email is missing or malformed.'});
  }

  if (!plainTextPassword) {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for User Register(Password is required) : ${email}`);
    return res.status(400).send({auth: false, message: 'Password is required.'});
  }

  const user = await User.findByPk(email);
  if (user) {
    console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for User Register(User already exists.) : ${email}`);
    return res.status(422).send({auth: false, message: 'User already exists.'});
  }

  const generatedHash = await generatePassword(plainTextPassword);

  const newUser = await new User({
    email: email,
    passwordHash: generatedHash,
  });

  const savedUser = await newUser.save();


  const jwt = generateJWT(savedUser);
  console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for User Register : ${email}`);
  res.status(201).send({token: jwt, user: savedUser.short()});
});

router.get('/', async (req: Request, res: Response) => {
  res.send('auth');
});

export const AuthRouter: Router = router;
