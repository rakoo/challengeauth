var Register = React.createClass({
  getInitialState: function() {
    return {}
  },

  click: function(e) {
    var login = this.refs.login.getDOMNode().value
    var password = this.refs.password.getDOMNode().value

    // Standard Uint8Array...
    var salt = nacl.randomBytes(32)
    // ... but SJCL wants a custom bitarray
    var sjclSalt = sjcl.codec.utf8String.toBits(salt)

    var privateKey = Uint8Array(sjcl.misc.pbkdf2(password, sjclSalt, 1000, 32 * 32))
    var pubKey = nacl.box.keyPair.fromSecretKey(privateKey).secretKey

    toSend = {
      login: login,
      salt: nacl.util.encodeBase64(salt),
      pubKey: nacl.util.encodeBase64(pubKey)
    }

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

    // Standard Uint8Array...
    var salt = nacl.randomBytes(32)
    // ... but SJCL wants a custom bitarray
    var sjclSalt = sjcl.codec.utf8String.toBits(salt)

    var privateKey = Uint8Array(sjcl.misc.pbkdf2(password, sjclSalt, 1000, 32 * 32))
    var pubKey = nacl.box.keyPair.fromSecretKey(privateKey).secretKey

    toSend = {
      login: login,
      salt: nacl.util.encodeBase64(salt),
      pubKey: nacl.util.encodeBase64(pubKey)
    }

    $.post("/login", toSend, function(o, st) {
      console.log(o, st)
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
