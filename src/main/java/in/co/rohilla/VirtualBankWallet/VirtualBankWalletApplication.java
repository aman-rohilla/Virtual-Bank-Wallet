package in.co.rohilla.VirtualBankWallet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCallback;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.google.gson.Gson;

import java.io.File;
import java.io.FileReader;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;






@SpringBootApplication
public class VirtualBankWalletApplication {
	public static void main(String[] args) {    
    
    SpringApplication.run(VirtualBankWalletApplication.class, args);

	}
}


@RestController
class API {

  private String sqlRegisterUser  = "INSERT INTO users(name, email, password) VALUES(?, ?, ?)";
  private String sqlFindUserByEmail  = "SELECT * FROM users where email = ?";
  private String sqlDepositMoney  = "UPDATE users SET balance = ((SELECT balance FROM users WHERE uid = ?) + ?) WHERE uid = ?";
  // private String sqlWithdrawMoney = "UPDATE users SET balance = ((SELECT balance FROM users WHERE uid = ?) - ?) WHERE uid = ?";


  private String sqlGetBalance    = "SELECT balance FROM users WHERE uid = ?";
  private String sqlUpdateBalance = "UPDATE users SET balance = ? WHERE uid = ?";
  private String sqlCreditTransaction = "INSERT INTO transactions(uid, type, amount) VALUES(?, 'CREDIT', ?)";  
  private String sqlDebitTransaction  = "INSERT INTO transactions(uid, type, amount) VALUES(?, 'DEBIT', ?)";  

  private String sqlGetAllTransactions = "SELECT * FROM transactions WHERE uid = ?";

  private PasswordEncoder encoder = new BCryptPasswordEncoder();
  public static final String SECRET = "SUPER_SECRET_KEY";
  public static final long EXPIRATION_TIME = 1000 * 3600 * 24 * 7; // 1 week
  private Gson gson = new Gson(); 

  private String indexHTML;
  private String registerHTML;
  private String loginHTML;

  @Autowired
  private JdbcTemplate jdbcTemplate;

  public API() throws Exception {
    Path indexPath    = FileSystems.getDefault().getPath("static"+File.separator+"index.html");
    Path registerPath = FileSystems.getDefault().getPath("static"+File.separator+"register.html");
    Path loginPath    = FileSystems.getDefault().getPath("static"+File.separator+"login.html");

    indexHTML     = new String(Files.readAllBytes(indexPath));
    registerHTML  = new String(Files.readAllBytes(registerPath));
    loginHTML     = new String(Files.readAllBytes(loginPath));
  }

  @GetMapping("/")
  public String homePage() {
    return indexHTML;
  }

  @GetMapping("/login")
  public String loginPage() {
    return loginHTML;
  }
  @GetMapping("/register")
  public String registerPage() {
    return registerHTML;
  }


  @PostMapping("/register")
  public Map<String, Object> register(@RequestBody Map<String, Object> body) {
    String name     = (String) body.get("name");
    String email    = (String) body.get("email");
    String password = (String) body.get("password");
    String hashedpass = encoder.encode(password);
    Boolean b = true;
    String message = "Account Created";

    try {
      jdbcTemplate.execute(sqlRegisterUser, new PreparedStatementCallback<Boolean>() {  
        @Override  
        public Boolean doInPreparedStatement(PreparedStatement ps) throws SQLException {  
          ps.setString(1, name);                  
          ps.setString(2, email);                  
          ps.setString(3, hashedpass);      
          ps.execute();
          return true;
        }  
      }); 

    } catch (Exception e) {
      if(e.getMessage().endsWith("[SQLITE_CONSTRAINT_UNIQUE]  A UNIQUE constraint failed (UNIQUE constraint failed: users.email)")) {
        message = email+" is already registered";
      } else {
        message = "UNKNOWN ERROR";
      }

      b = false;
    }

    SortedMap<String, Object> res = new TreeMap<>();
    res.put("success", b);
    res.put("message", message);
    return res;
  }


@PostMapping("/login")
  public Map<String, Object> login(@RequestBody Map<String, Object> body, HttpServletResponse res) {
    String email      = (String) body.get("email");
    String password   = (String) body.get("password");
    ApiResponse apiRes = new ApiResponse("Login Successful!", true);
    User user = new User();

    jdbcTemplate.execute(sqlFindUserByEmail, new PreparedStatementCallback<Boolean>() {  
      @Override  
      public Boolean doInPreparedStatement(PreparedStatement ps) {  
        try {
          ps.setString(1, email);
          var rs =  ps.executeQuery();

          if(rs.next()) {
            String hashedPass = rs.getString("password");
            user.uid = rs.getLong("uid");
            user.name = rs.getString("name");
            // user.email = rs.getString("email");
            // user.balance = rs.getDouble("balance");

            if(! BCrypt.checkpw(password, hashedPass)) {
              apiRes.success = false;
              apiRes.message = "Password is incorrect";   
            }
          } else {
            apiRes.success = false;
            apiRes.message = email+" is not registered";   
          }
          rs.close();
        } catch (Exception e) {
          if(e.getMessage().equals("[SQLITE_CONSTRAINT_UNIQUE]  A UNIQUE constraint failed (UNIQUE constraint failed: users.email)")) {
            apiRes.success = false;
            apiRes.message = email+" is already registered";
          } else {
            apiRes.success = false;
            apiRes.message = "UNKNOWN ERROR";
          }
        }

        return true;
      }  
    });  

    if(apiRes.success == true) {
      SortedMap<String, Object> userMap = new TreeMap<>();
      userMap.put("uid", user.uid);
      userMap.put("name", user.name);

      String jsonStr = gson.toJson(userMap); 

      String token
      = JWT.create()
        .withSubject(jsonStr)
        .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
        .sign(Algorithm.HMAC512(SECRET.getBytes()));

      String expiresStr = DateTimeFormatter.RFC_1123_DATE_TIME.format(OffsetDateTime.now(ZoneOffset.UTC).plus(Duration.ofHours(24*7)));
      res.addHeader("Set-Cookie", "token=" + token + "; Expires=" + expiresStr + "; Path=/; HTTPOnly");
      res.addHeader("Set-Cookie", "username=" + user.name.replaceAll(";", "-") + "; Expires=" + expiresStr + "; Path=/;");
    }

    return apiRes.toMap();
  }
  @GetMapping("/logout")
  public Map<String, Object> logout(HttpServletResponse res) {
    Cookie cookie = new Cookie("token", null);
    cookie.setPath("/");
    cookie.setHttpOnly(true);
    cookie.setMaxAge(0);
    res.addCookie(cookie);

    Cookie userCookie = new Cookie("username", null);
    userCookie.setPath("/");
    userCookie.setHttpOnly(false);
    userCookie.setMaxAge(0);
    res.addCookie(userCookie);
    return new ApiResponse("Logged Out", true).toMap();
  }

  public DecodedPayload decodePayload(HttpServletRequest req) {
    DecodedPayload decodedPayload = new DecodedPayload();
    String token = req.getHeader("token");
    System.out.println(token);
    System.out.println(req.getHeader("username"));

    if(null == token) {
      decodedPayload.error = true;
      return decodedPayload;
    }

    try {
      String payload = 
        JWT.require(Algorithm.HMAC512(SECRET.getBytes()))
        .build()
        .verify(token)
        .getSubject();

      DecodedUser user = gson.fromJson(payload, DecodedUser.class);
      decodedPayload.user = user;
    } catch (JWTVerificationException e) {
      decodedPayload.error = true;
    }
    return decodedPayload;
  }


  // @PostMapping("/deposit")
  // public Map<String, Object> deposit(@RequestBody Map<String, Object> body, HttpServletRequest req) {
  //   DecodedPayload payload = decodePayload(req);
  //   if(payload.error) {
  //     return new ApiResponse("Unauthorized", false).toMap();
  //   }
    

  //   ApiResponse apiRes = new ApiResponse("Deposited", true);
  //   try {
  //     jdbcTemplate.execute(sqlDepositMoney, new PreparedStatementCallback<Boolean>() {  
  //       @Override  
  //       public Boolean doInPreparedStatement(PreparedStatement ps) throws SQLException {  
  //         double amount;
  //         try {
  //           amount = (Double) body.get("amount");
  //         } catch (Exception e) {
  //           amount = (Integer) body.get("amount");
  //         }
  //         long userID = payload.user.uid;
  //         ps.setLong(1, userID);                  
  //         ps.setDouble(2, amount);                  
  //         ps.setLong(3, userID);      
  //         ps.setLong(4, userID);      
  //         // ps.setDouble(5, amount);                  
  //         ps.execute();
  //         return true;
  //       }  
  //     });  
  //   } catch (Exception e) {      
  //     System.out.println(e.getMessage());
  //     apiRes.message = "UNKNOWN ERROR";
  //     apiRes.success = false;
  //   }    



  //   return apiRes.toMap();
  // }


  @PostMapping("/deposit")
  public Map<String, Object> deposit(@RequestBody Map<String, Object> body, HttpServletRequest req) {
    DecodedPayload payload = decodePayload(req);
    if(payload.error) {
      return new ApiResponse("Unauthorized", false).toMap();
    }
    
    ApiResponse apiRes = new ApiResponse("Deposited", true);
    long userID = payload.user.uid;
    double amount;
    try {
      amount = (Double) body.get("amount");
    } catch (Exception e) {
      amount = (Integer) body.get("amount");
    }

    try {
      Connection conn = jdbcTemplate.getDataSource().getConnection();
      PreparedStatement psDepositMoney = conn.prepareStatement(sqlDepositMoney);
      psDepositMoney.setLong(1, userID);
      psDepositMoney.setDouble(2, amount);
      psDepositMoney.setLong(3, userID);

      PreparedStatement psCredit = conn.prepareStatement(sqlCreditTransaction);
      psCredit.setLong(1, userID);
      psCredit.setDouble(2, amount);

      conn.setAutoCommit(false);
      try {
        psDepositMoney.execute();
        psCredit.execute();
        conn.commit();
        conn.setAutoCommit(true);

      } catch (Exception ex) {

        conn.rollback();
        conn.setAutoCommit(true);
        apiRes.message = "UNKNOWN ERROR";
        apiRes.success = false;
      }
      conn.close();
    } catch (Exception e) {      
      apiRes.message = "UNKNOWN ERROR";
      apiRes.success = false;
    }    

    return apiRes.toMap();
  }

  // @PostMapping("/withdraw")
  // public Map<String, Object> withdraw(@RequestBody Map<String, Object> body, HttpServletRequest req) {
  //   DecodedPayload payload = decodePayload(req);
  //   if(payload.error) {
  //     return new ApiResponse("Unauthorized", false).toMap();
  //   }
    
  //   ApiResponse apiRes = new ApiResponse("Withdrawn", true);
  //   try {
  //     jdbcTemplate.execute(sqlWithdrawMoney, new PreparedStatementCallback<Boolean>() {  
  //       @Override  
  //       public Boolean doInPreparedStatement(PreparedStatement ps) throws SQLException {  
  //         double amount;
  //         try {
  //           amount = (Double) body.get("amount");
  //         } catch (Exception e) {
  //           amount = (Integer) body.get("amount");
  //         }
  //         long userID = payload.user.uid;
  //         ps.setLong(1, userID);                  
  //         ps.setDouble(2, amount);                  
  //         ps.setLong(3, userID);  
  //         ps.setLong(4, userID);      
  //         ps.setDouble(5, amount);                      
  //         ps.execute();
  //         return true;
  //       }  
  //     });  
  //   } catch (Exception e) {
  //     System.out.println(e.getMessage());
  //     if(e.getMessage().endsWith("A RAISE function within a trigger fired, causing the SQL statement to abort (Not Enough Balance)")) {
  //       apiRes.message = "Not Enough Balance";
  //     } else {
  //       apiRes.message = "UNKNOWN ERROR";
  //     }

  //     apiRes.success = false;
  //   }    

  //   return apiRes.toMap();
  // }
  
  @PostMapping("/withdraw")
  public Map<String, Object> withdraw(@RequestBody Map<String, Object> body, HttpServletRequest req) {
    DecodedPayload payload = decodePayload(req);
    if(payload.error) {
      return new ApiResponse("Unauthorized", false).toMap();
    }
    
    ApiResponse apiRes = new ApiResponse("Withdrawn", true);
    long userID = payload.user.uid;
    double amount;
    try {
      amount = (Double) body.get("amount");
    } catch (Exception e) {
      amount = (Integer) body.get("amount");
    }

    try {
      Connection conn = jdbcTemplate.getDataSource().getConnection();
      
      PreparedStatement psGetBalance = conn.prepareStatement(sqlGetBalance);
      psGetBalance.setLong(1, userID);

      PreparedStatement psUpdateBalance = conn.prepareStatement(sqlUpdateBalance);
      psUpdateBalance.setLong(2, userID);
      

      PreparedStatement psDebit = conn.prepareStatement(sqlDebitTransaction);
      psDebit.setLong(1, userID);
      psDebit.setDouble(2, amount);

      conn.setAutoCommit(false);
      try {
        psGetBalance.execute();
        ResultSet results = psGetBalance.getResultSet();
        Double currentBalance;
        results.next();
        currentBalance = results.getDouble("balance");
        results.close();

        Double updatedBalance = currentBalance - amount;
        if(updatedBalance < 0) {
          throw new Exception("Not Enough Balance");
        }

        psUpdateBalance.setDouble(1, updatedBalance);
        psUpdateBalance.execute();
        psDebit.execute();
        conn.commit();
        conn.setAutoCommit(true);

      } catch (Exception e) {

        conn.rollback();
        conn.setAutoCommit(true);

        if(e.getMessage().equals("Not Enough Balance")) {
          apiRes.message = "Not Enough Balance";
        } else {
          apiRes.message = "UNKNOWN ERROR";
        }
        apiRes.success = false;
      }
      conn.close();
    } catch (Exception e) {      
      apiRes.message = "UNKNOWN ERROR";
      apiRes.success = false;
    }    

    return apiRes.toMap();
  }

  @GetMapping("/transactions")
  public Map<String, Object> getAllTransactions(HttpServletRequest req) {
    DecodedPayload payload = decodePayload(req);
    if(payload.error) {
      return new ApiResponse("Unauthorized", false).toMap();
    }
    
    ApiResponse apiRes = new ApiResponse("None", true);
    long userID = payload.user.uid;
    List<Map<String, Object>> transactions = new ArrayList<>();
    
    String currentTime = DateTimeFormatter.RFC_1123_DATE_TIME.format(OffsetDateTime.now(ZoneOffset.UTC));
    try {
      jdbcTemplate.execute(sqlGetAllTransactions, new PreparedStatementCallback<Boolean>() {  
        @Override  
        public Boolean doInPreparedStatement(PreparedStatement ps) throws SQLException {  
          ps.setLong(1, userID);     

          ResultSet results = ps.executeQuery();
          
          while(results.next()) {
            SortedMap<String, Object> transaction = new TreeMap<>();
            transaction.put("type", results.getString("type"));
            transaction.put("amount", results.getDouble("amount"));
            transaction.put("timestamp", results.getString("timestamp"));
            transactions.add((transaction));
          }
          results.close();
          return true;
        }  
      }); 

    } catch (Exception e) {
      apiRes.message = "UNKNOWN ERROR";
      apiRes.success = false;
    }

    var resJson = apiRes.toMap();
    resJson.put("transactions", transactions);
    return resJson;
  }


}


class ApiResponse{
  String message;
  Boolean success;
  ApiResponse(String message, Boolean success) {
    this.message = message;
    this.success = success;
  }

  Map <String, Object> toMap(){
    SortedMap<String, Object> map= new TreeMap<>();
    map.put("success", success);
    map.put("message", message);
    return map;
  }
}

class User {
  long uid;
  String name;
  String email;
  double balance;
}

class DecodedUser{
  public long uid;
  public String name;
}

class DecodedPayload{
  public Boolean error = false;
  public DecodedUser user;
}