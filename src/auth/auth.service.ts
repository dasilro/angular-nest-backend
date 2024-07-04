import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto, UpdateAuthDto, RegisterUserDto, LoginDto } from './dto';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
    ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    console.log(createUserDto);
    try {
      const { password, ...userData } = createUserDto;
      
      // 1.- Encriptar contraseña
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      // 2.- Guardar el usuario      
      await newUser.save();      
      const { password:_, ...user } = newUser.toJSON();

      return user;
    } catch (error) {
      if (error.code === 11000){
        throw new BadRequestException(`${createUserDto.email} already exists`);
      } 
      throw new InternalServerErrorException('Something terrible happen');     
    }    
  }

  async login(loginDto: LoginDto): Promise<LoginResponse>{
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({email});

    if (!user){
      throw new UnauthorizedException('Not valid credentials');
    }

    if (!bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('Not valid credentials');
    }

    const { password: _ , ...userData} = user.toJSON();

    return {user: userData, token: this.getJwtToken({id: user.id})};
  }

  // async checkToken(email: string): Promise<LoginResponse>{

  //   const user = await this.userModel.findOne({email});

  //   if (!user){
  //     throw new UnauthorizedException('Not valid credentials');
  //   }

  //   const { password: _ , ...userData} = user.toJSON();

  //   return {user: userData, token: this.getJwtToken({id: user.id})};
  // }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create({...registerUserDto});
    return await this.login({ email: user.email, password: registerUserDto.password});
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  async findUserById(id: string){
    const user = await this.userModel.findById(id);
    const { password:_, ...rest} = user.toJSON();
    return rest;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payLoad: JwtPayload){
    const token = this.jwtService.sign(payLoad);
    return token;
  }
}
