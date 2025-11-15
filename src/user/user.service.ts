import { Injectable } from '@nestjs/common'
import { Model } from 'mongoose'
import { UserDocument, UserModel } from './user.model'
import { InjectModel } from '@nestjs/mongoose'
import { IUser } from '../shared/types/user.types'

@Injectable()
export class UserService {
  constructor(
    @InjectModel(UserModel.name)
    private readonly userModel: Model<UserDocument>
  ) {}
  public async findByUsername(username: string): Promise<IUser | null> {
    return await this.userModel.findOne<IUser>({ username }).exec()
  }

  public async saveUser(data: IUser): Promise<IUser> {
    const created = await this.userModel.create(data)
    return created.toObject()
  }
}
