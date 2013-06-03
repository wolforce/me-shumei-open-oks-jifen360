package me.shumei.open.oks.jifen360;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONException;
import org.json.JSONObject;
import org.jsoup.Connection.Method;
import org.jsoup.Connection.Response;
import org.jsoup.Jsoup;

import android.content.Context;

/**
 * 使签到类继承CommonData，以方便使用一些公共配置信息
 * @author wolforce
 *
 */
public class Signin extends CommonData {
	String resultFlag = "false";
	String resultStr = "未知错误！";
	
	String user;
	String pwd;
	private String loginQid;//360的qid号
	private boolean isLoginSucceed = false;//登录是否成功
	
	
	/**
	 * <p><b>程序的签到入口</b></p>
	 * <p>在签到时，此函数会被《一键签到》调用，调用结束后本函数须返回长度为2的一维String数组。程序根据此数组来判断签到是否成功</p>
	 * @param ctx 主程序执行签到的Service的Context，可以用此Context来发送广播
	 * @param isAutoSign 当前程序是否处于定时自动签到状态<br />true代表处于定时自动签到，false代表手动打开软件签到<br />一般在定时自动签到状态时，遇到验证码需要自动跳过
	 * @param cfg “配置”栏内输入的数据
	 * @param user 用户名
	 * @param pwd 解密后的明文密码
	 * @return 长度为2的一维String数组<br />String[0]的取值范围限定为两个："true"和"false"，前者表示签到成功，后者表示签到失败<br />String[1]表示返回的成功或出错信息
	 */
	public String[] start(Context ctx, boolean isAutoSign, String cfg, String user, String pwd) {
		//把主程序的Context传送给验证码操作类，此语句在显示验证码前必须至少调用一次
		CaptchaUtil.context = ctx;
		//标识当前的程序是否处于自动签到状态，只有执行此操作才能在定时自动签到时跳过验证码
		CaptchaUtil.isAutoSign = isAutoSign;
		
		try{
			//存放Cookies的HashMap
			HashMap<String, String> cookies = new HashMap<String, String>();
			//Jsoup的Response
			Response res;
			
			String growthPageUrl = "http://jifen.360.cn/index/growth";//个人中心页面URL，从此页面可以提取出访问签到URL用的token
			String getCurrentPointUrl = "http://gate.wan.360.cn/me/score";//查看现有积分数
			String checkSignStatusUrl = "http://jifen.360.cn/index/ajax_signin_count.html";//检查当前账号是否已经签过到的URL
			String signinUrl = "http://jifen.360.cn/index/ajax_signin.html?token=";//提交签到请求的URL
			
			//调用360通行证登录函数
			this.user = user;
			this.pwd = pwd;
			cookies = login360();
			if(isLoginSucceed)
			{
				//查看现有积分数
				//{"errno":0,"errmsg":"","data":124}
				res = Jsoup.connect(getCurrentPointUrl).cookies(cookies).userAgent(UA_ANDROID).timeout(TIME_OUT).ignoreContentType(true).method(Method.GET).execute();
				int currentPoint = new JSONObject(res.body()).getInt("data");
				
				//检查今天是否已经签过到
				//{"errno":0,"errmsg":"","data":{"signin_count":220188,"ifsignin":false}}
				//{"errno":0,"errmsg":"","data":{"signin_count":146144,"ifsignin":true,"dayslen":3}}
				res = Jsoup.connect(checkSignStatusUrl).cookies(cookies).userAgent(UA_ANDROID).timeout(TIME_OUT).ignoreContentType(true).method(Method.GET).execute();
				cookies.putAll(res.cookies());
				System.out.println(res.body());
				JSONObject jsonObj = new JSONObject(res.body()).getJSONObject("data");
				boolean ifsignin = jsonObj.getBoolean("ifsignin");
				
				if(ifsignin)
				{
					//今天已签过到
					int dayslen = jsonObj.getInt("dayslen");
					this.resultFlag = "true";
					this.resultStr = "今天已签过到，现有" + currentPoint + "积分，共签" + dayslen + "天";
				}
				else
				{
					//今天还没签到，那就访问个人中心页面提取出token，再进行签到
					res = Jsoup.connect(growthPageUrl).cookies(cookies).userAgent(UA_ANDROID).timeout(TIME_OUT).ignoreContentType(true).method(Method.GET).execute();
					cookies.putAll(res.cookies());
					
					//用正则查找token
					//"token":"4643701c49b432e6a9f3d366e0481234"
					//4643701c49b432e6a9f3d366e0481234
					Pattern pattern = Pattern.compile("\"token\":\"([0-9a-zA-Z]+)\"");
					Matcher matcher = pattern.matcher(res.parse().html());
					String token = null;
					if(matcher.find())
					{
						token = matcher.group(1);
					}
					
					//拼接出完整的签到URL，然后签到
					//http://jifen.360.cn/index/ajax_signin.html?token=4643701c49b432e6a9f3d366e0481234
					//{"errno":0,"errmsg":"","data":{"dayslen":1,"score":2,"signin_count":216179}} 正常签到
					//{"errno":0,"errmsg":"","data":{"dayslen":1,"score":2,"name":"\u5927\u5c06\u519b\u7b7e\u5230\u793c\u5305","intro":"\u300a\u5927\u5c06\u519b\u300b\u5e78\u8fd0\u7b7e\u5230\u793c\u5305","domain":"http:\/\/rd.wan.360.cn\/reg?src=jifen-cj-djj","gkey":"djj","cardnum":"WHYFOQ501OAF9TXHK3","remark":"1\u3001\u70b9\u51fb\u6e38\u620f\u754c\u9762\u53f3\u4e0a\u65b9\u6d3b\u52a8\u4e00\u89c8\u6309\u94ae::SPR::http:\/\/p7.qhimg.com\/t01e61f7b63048d2167.jpg::SPR::2\u3001\u9009\u62e9\u5404\u7c7b\u793c\u5305\u9886\u53d6\uff0c\u8f93\u5165\u793c\u5305\u6fc0\u6d3b\u7801\u5373\u53ef::SPR::http:\/\/p0.qhimg.com\/t01434ccbfdb0fa592a.jpg","signin_count":196036}} 中奖签到
					//{"errno":1,"errmsg":"\u60a8\u4eca\u5929\u5df2\u7ecf\u7b7e\u8fc7\u5230\u4e86~","data":""} 已签过到
					//{"errno":-1,"errmsg":"\u60a8\u7684\u5e10\u53f7\u5b58\u5728\u5f02\u5e38\uff0c\u8bf7\u91cd\u65b0\u767b\u5f55\uff01","data":""} 登录异常
					signinUrl = signinUrl + token;
					System.out.println(token);
					res = Jsoup.connect(signinUrl).data("token", token).cookies(cookies).userAgent(UA_ANDROID).timeout(TIME_OUT).ignoreContentType(true).method(Method.POST).execute();
					jsonObj = new JSONObject(res.body());
					System.out.println(res.body());
					int errno = jsonObj.getInt("errno");
					if(errno == 0)
					{
						JSONObject dataObj = jsonObj.getJSONObject("data");
						int dayslen = dataObj.getInt("dayslen");
						int score = dataObj.getInt("score");
						currentPoint += score;
						
						//整理中奖信息，有可能在转换JSON的时候格式会出错，要捕获一下异常
						StringBuilder sb = new StringBuilder();
						sb.append("签到成功");
						sb.append("增加" + score + "积分，");
						sb.append("现有" + currentPoint + "积分，");
						sb.append("共签" + dayslen + "天");
						if(dataObj.length() > 3)
						{
							sb.append("\n签到中奖，中奖信息：\n");
							for(Iterator iter = jsonObj.keys(); iter.hasNext();)
							{
								String key = (String) iter.next();
								if(!key.equals("dayslen") && !key.equals("score") && !key.equals("signin_count"))
								{
									try {
										sb.append(key);
										sb.append(":");
										sb.append(jsonObj.getString(key));
										sb.append("\n");
									} catch (Exception e) {
										e.printStackTrace();
									}
								}
							}
						}
						resultFlag = "true";
						resultStr = sb.toString();
					}
					else if(errno == 1)
					{
						resultFlag = "true";
						resultStr = "今日已签过到，现有" + currentPoint + "积分";
					}
					else if(errno == -1)
					{
						resultFlag = "false";
						resultStr = "登录成功，提交签到数据时出现数据异常，签到失败";
					}
				}
			}
			
		
		} catch (JSONException e) {
			this.resultFlag = "false";
			this.resultStr = "登录成功但提交签到请求后，服务器返回错误信息";
			e.printStackTrace();
		} catch (IOException e) {
			this.resultFlag = "false";
			this.resultStr = "连接超时";
			e.printStackTrace();
		} catch (Exception e) {
			this.resultFlag = "false";
			this.resultStr = "未知错误！";
			e.printStackTrace();
		}
		
		return new String[]{resultFlag, resultStr};
	}
	
	
	
	/**
	 * 登录360通行证
	 * http://i.360.cn/login/
	 * 登录步骤
	 * 1.手动构造两个Cookies：i360loginName=wolforce%2540foxmail.com，trad=0
	 * 2.用构造出的Cookies访问获取全局token的链接：http://login.360.cn/?o=sso&m=getToken&func=QHPass.loginUtils.tokenCallback&userName=shumei%40foxmail.com&rand=0.657428435748443&callback=QiUserJsonP1350462351234
	 * 3.提取出token值，加入到链接中：http://login.360.cn/?o=sso&m=login&from=i360&rtype=data&func=QHPass.loginUtils.loginCallback&userName=shumei%40foxmail.com&password=c94210819524e90f3cdd65fd1786dddd&isKeepAlive=0&token=ca925dc9dd1a5123&captFlag=&r=
	 * userName是用户名经过encodeURIComponent编码的字符串
	 * password是经过32位md5加密的密码
	 * token是第2步中获取出的token值
	 * @return HashMap<String, String>
	 */
	public HashMap<String, String> login360(){
		String user_encoded;
		String pwd_encrypted;
		HashMap<String, String> cookies = new HashMap<String, String>();
		
		try {
			//编码用户名，32位md5加密密码
			user_encoded = URLEncoder.encode(user, "UTF-8");
			pwd_encrypted = MD5.md5(pwd);
			
			Response res;
			String golbalTokenUrl = "http://login.360.cn/?o=sso&m=getToken&func=QHPass.loginUtils.tokenCallback&userName=" + user_encoded;//获取全局token的URL
			String loginUrl;//用全局token登录账号的URL
			cookies.put("i360loginName", user_encoded);
			cookies.put("trad", "0");
			
			try {
				//先用账号获取临时token字符串
				res = Jsoup.connect(golbalTokenUrl).cookies(cookies).userAgent(UA_ANDROID).timeout(TIME_OUT).method(Method.GET).ignoreContentType(true).execute();
				
				//提取临时token
				//{"errno":0,"errmsg":"","token":"f6123404fdb1a222"}
				String tokenCallbackStr = res.body().replace("QHPass.loginUtils.tokenCallback(", "").replace("})", "}");
				String token = new JSONObject(tokenCallbackStr).getString("token");
				
				//使用全局token登录网站，获取名为T和Q的cookie
				loginUrl = "http://login.360.cn/?o=sso&m=login&from=i360&rtype=data&func=QHPass.loginUtils.loginCallback&isKeepAlive=0&captFlag=&r=&" +
						"&userName=" + user_encoded +
						"&password=" + pwd_encrypted +
						"&token=" + token;
				res = Jsoup.connect(loginUrl).cookies(cookies).userAgent(UA_ANDROID).timeout(TIME_OUT).ignoreContentType(true).method(Method.GET).execute();
				cookies.putAll(res.cookies());
				
				//{"errno":0,"errmsg":"","s":"e27V.%60togp%3F%2BeADa","userinfo":{"qid":"154601234","userName":"360U154601234","nickName":"","realName":"","imageId":"190144aq111234","theme":"360","src":"yunpan","type":"formal","loginEmail":"shumei@shumei.me","loginTime":"1350483069","isKeepAlive":"0","crumb":"af446e","imageUrl":"http:\/\/u1.qhimg.com\/qhimg\/quc\/48_48\/22\/02\/55\/220255dq1234.3eceac.jpg"}}
				//{"errno":220,"errmsg":"\u767b\u5f55\u5bc6\u7801\u9519\u8bef\uff0c\u8bf7\u91cd\u65b0\u8f93\u5165"}
				//{"errno":1036,"errmsg":"\u5e10\u53f7\u4e0d\u5b58\u5728"}
				String loginCallbackStr = res.parse().text().replace("QHPass.loginUtils.loginCallback(", "").replace("})", "}");
				System.out.println(loginCallbackStr);
				JSONObject callBackObj = new JSONObject(loginCallbackStr);
				int errno = callBackObj.getInt("errno");
				if(errno == 0)
				{
					String qid = callBackObj.getJSONObject("userinfo").getString("qid");
					loginQid = qid;//保存qid给后续操作用
					isLoginSucceed = true;//登录成功
				}
				else if(errno == 220)
				{
					resultFlag = "false";
					resultStr = "密码错误";
				}
				else if(errno == 1060)
				{
					resultFlag = "false";
					resultStr = "密码不合法";
				}
				else if(errno == 8201)
				{
					resultFlag = "false";
					resultStr = "无效的登录";
				}
				else if(errno == 1036)
				{
					resultFlag = "false";
					resultStr = "账号不存在";
				}
				else
				{
					resultFlag = "false";
					resultStr = "已签过到";
				}
			} catch (JSONException e) {
				resultFlag = "false";
				resultStr = "登录失败";
				e.printStackTrace();
			}
		} catch (IOException e) {
			this.resultFlag = "false";
			this.resultStr = "连接超时";
			e.printStackTrace();
		}
		
		return cookies;
	}
	
	
}
