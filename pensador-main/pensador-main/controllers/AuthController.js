const User = require('../models/User')

//criptografar a senha
const bcrypt = require('bcryptjs')

module.exports = class AuthController{
  static login(request, response){
    return response.render('auth/login')
  }
  static register(request, response){
    return response.render('auth/register')
  }

  static async regsiterpost(request, response){
    const {name, email, password, confirmepassword} = request.body

// 1 validação de senha - password math
if(password != confirmpassword){
request.flash('message', ' as senha não conferem, tente novamente')
Response.render('auth/register')
return
}

//2 vqlidação de email - 

//3 validação criptografia do password 
// salt = quantidade de caracteres extras na cript
const salt = bcrypt.genSaltSync(10)
const hashedPassword = bcrypt.hashSync(password, salt)

//4 criar usuario no banco
const User = {
  name,
  email,
  password:hashedPassword
}

try {
  await User.create(user)
  request.flash('message', 'cadastro realizado comn sucesso!')
  response.redirect('/')
  return
} catch (error) {
  console.log(error)
}
//5  regra de negocio do app

  }

}
