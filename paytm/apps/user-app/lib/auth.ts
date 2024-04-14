import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaClient } from "@repo/db/client";
import bcrypt from "bcrypt";
import { JWT } from "next-auth/jwt";
import { DefaultSession, Session } from "next-auth";

const client = new PrismaClient();


interface PaytmSession extends Session
{
    user?: {
        id?: string | null
        name?: string | null
        email?: string | null
        image?: string | null
      }
}

const authOptions = {
    providers: [
      CredentialsProvider({
        name: 'Credentials',
          credentials: {
            phone: { label: "Phone number", type: "text", placeholder: "1231231231" },
            password: { label: "Password", type: "password" }
          },
          async authorize(credentials: any) {
            const hashedPassword = await bcrypt.hash(credentials.password , 10);
            const existingUser = await client.user.findFirst({
                where :
                {
                    number : credentials.phone
                }
            });

            if(existingUser)
            {
                const passwordValidation = await bcrypt.compare(hashedPassword , existingUser.password);
                if(passwordValidation)
                {
                    return {id : existingUser.id.toString(),
                            name: existingUser.name,
                            email: existingUser.email
                    }       
                }
                return null;
            }


            try
            {
                const newUser = await client.user.create({
                    data: {
                        number : credentials.number,
                        password : hashedPassword
                    }
                });

                return {
                    id : newUser.id.toString(),
                    name : newUser.name,
                    email : newUser.email
                }
            }catch(err : any)
            {
                console.log(err);
            }
            return null;
          }
      })
    ],
    secret: process.env.JWT_SECRET || "S3CR3T",
    callbacks : {
        async session({ token, session }: {token : JWT , session : PaytmSession}) {
          
            if(session.user != null)
                session.user.id = token.sub;
            return session
        }
    }
}

export default authOptions;