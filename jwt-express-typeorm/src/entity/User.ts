import { IsNotEmpty, Length } from "class-validator"
import { Entity, PrimaryGeneratedColumn, Column, Unique, UpdateDateColumn } from "typeorm"
import *  as bcrypt from 'bcryptjs'


@Entity()
@Unique('username')
export class User {

  @PrimaryGeneratedColumn()
  id: number

  @Column()
  @Length(4, 20)
  username: string

  @Column()
  @Length(4, 100)
  password: string

  @Column()
  @IsNotEmpty()
  role: string

  @Column()
  @UpdateDateColumn()
  updateAt: data

  hashpassword() {
    return this.password = bcrypt.hash(this.password, 8)
  }

  checkIfUnencryptedPasswordIsValid(unencryptedPassword: string) {
    return bcrypt.compare(unencryptedPassword, this.password)
  }


}
