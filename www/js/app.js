var Register = React.createClass({
  getInitialState: function() {
    return {}
  },

  click: function(e) {
    var login = this.refs.login.getDOMNode().value
    var password = this.refs.password.getDOMNode().value

    var salt = sjcl.random.randomWords(8)
    var seed = Uint8Array(sjcl.misc.pbkdf2(password, salt, 1000, 32 * 32))
    var pubKey = nacl.sign.keyPair.fromSeed(seed).publicKey

    toSend = {
      login: login,
      salt: sjcl.codec.base64.fromBits(salt),
      pubKey: nacl.util.encodeBase64(pubKey)
    }

    console.log("Registering:", JSON.stringify(toSend))

    $.post("/register", toSend, function(o, st) {
      console.log(o, st)
    })
  },

  render: function() {
    return <form className="form-signin">
             <h2 className="form-signin-heading">Please register</h2>
             <input 
               type="text"
               id="inputLogin"
               className="form-control"
               placeholder="Login"
               ref="login"
               required
               autofocus/>

             <input
               type="password"
               id="inputPassword"
               className="form-control"
               placeholder="Password"
               ref="password"
               required/>

             <button className="btn btn-lg btn-primary btn-block" type="button" onClick={this.click}>Register</button>
          </form>
  }
});

var Login = React.createClass({
  click: function() {
    var login = this.refs.login.getDOMNode().value
    var password = this.refs.password.getDOMNode().value

    $.post("/login", {login: login}, function(data) {
      var challenge = JSON.parse(data)

      var salt = sjcl.codec.base64.toBits(challenge.salt)
      var seed = Uint8Array(sjcl.misc.pbkdf2(password, salt, 1000, 32 * 32))
      var secretKey = nacl.sign.keyPair.fromSeed(seed).secretKey

      var token = nacl.util.decodeBase64(challenge.token)
      var sig = nacl.sign.detached(token, secretKey)

      var toSend = {
        login: login,
        token: challenge.token,
        sig: nacl.util.encodeBase64(sig),
      }

      $.post("/login", toSend, function(o, data) {
        if (data == "success") {
          console.log("Logged in!")
        } else {
          console.log("Couldn't log in!")
        }
      })

    })
  },

  render: function() {
    return <form className="form-signin">
             <h2 className="form-signin-heading">Please login</h2>
             <input 
               type="text"
               id="inputLogin"
               className="form-control"
               placeholder="Login"
               ref="login"
               required
               autofocus/>

             <input
               type="password"
               id="inputPassword"
               className="form-control"
               placeholder="Password"
               ref="password"
               required/>

             <button className="btn btn-lg btn-primary btn-block" type="button" onClick={this.click}>Log in</button>
          </form>
  }
});

var App = React.createClass({
  getInitialState: function() {
    var page;
    switch(window.location.pathname) {
    case "/register": 
      page = "register"
      break;
    case "/login":
      page = "login"
      break;
    }
    return {page: page}
  },

  render: function() {
return <div>
  <nav className="navbar navbar-default">
    <div id="navbar" className="container-fluid">
      <ul className="nav navbar-nav">
        <li><a href="#">Home</a></li>
        <li className={this.state.page == "register" ? "active": ""}>
          <a href="/register">Register</a>
        </li>
        <li className={this.state.page == "login" ? "active": ""}>
          <a href="/login">Login</a>
        </li>
      </ul>
    </div>
  </nav>
  {this.state.page == "register" ? <Register /> : <Login />}
</div>

  }
});

React.render(<App />, document.getElementById('container'));
