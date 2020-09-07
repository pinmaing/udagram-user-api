import {Router, Request, Response} from 'express';
import { v4 as uuid } from 'uuid'
import {User} from '../models/User';
import {AuthRouter} from './auth.router';

const router: Router = Router();

router.use('/auth', AuthRouter);

router.get('/');

router.get('/:id', async (req: Request, res: Response) => {
  const {id} = req.params;
  let pid = uuid();
  console.log(new Date().toLocaleString() + `: ${pid} - Requested for getting User ID : ${id}`);
  
  const item = await User.findByPk(id);
  console.log(new Date().toLocaleString() + `: ${pid} - Finished processing request for getting User ID : ${id}`);
  
  res.send(item);
});

export const UserRouter: Router = router;
