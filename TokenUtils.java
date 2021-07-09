package com.skirmisher.wind.Tools;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.lang.reflect.Field;
import java.util.*;

/**
 * @Author :ian
 * @Description : token creator and token verification
 * @Date :created in 2021/7/6
 */
public class TokenUtils {
    public  static SignatureAlgorithm DefaultAlgorithm=SignatureAlgorithm.HS256;;
    public  SignatureAlgorithm algorithm=SignatureAlgorithm.HS256;;
    public static Map<String,Object>getField_map(Object obj){
        /*
         getDeclaredFields:可以获取本类所有的字段，包括private的，
                           但是不能获取继承来的字段。 (注： 这里只能获取到private的字段，
                           但并不能访问该private字段的值,除非加上setAccessible(true))
                 getFields:只能获取public的，包括从父类继承来的字段
         */
        HashMap<String,Object>map=new HashMap<>();
        Field[]fields=obj.getClass().getDeclaredFields();
        for(Field f:fields){
            f.setAccessible(true);
            try {
                map.put(f.getName(),f.get(obj));
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            }
        }
        return map;
    }

    /**
     *
     * @param obj :if you want to get the fields and its value of the object
     * @return return the ArrayList<ArrayList<Object>>res,
     *         res.get(0):fields name
     *         res.get(1):fields value
     */
    public ArrayList<ArrayList<Object>>getField_list(Object obj){
        ArrayList<ArrayList<Object>>lists=new ArrayList<>();
        ArrayList<Object>names=new ArrayList<>();
        ArrayList<Object>values=new ArrayList<>();
        Field[]fields=obj.getClass().getDeclaredFields();
        for(Field f:fields){
            f.setAccessible(true);
            try {
                names.add(f.getName());
                f.setAccessible(true);
                values.add(f.get(obj));
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            }
        }
        //index 0:field name
        lists.add(names);
        //index 1:field value
        lists.add(values);
        return lists;
    }

    /**
     *
     * @param obj java bean, containing the information that need to
     *            store in the token
     * @param secretFieldName if you want to get the field in the bean obj
     *                        to be the secret
     * @param subjectFieldName if you want to get the field in the bean obj
     *                         to be the Issuer
     * @param idFieldName if you want to get the field in tne bean obj
     *                    to be the id, the id will be distributed a random
     *                    value if {@code null}
     * @param lastingTime define the lasting time of the token (ms)
     * @return the token string
     * @throws Exception if the secret is {@code null}
     */
    public String createTokenWithObj(Object obj,String secretFieldName,String subjectFieldName,String idFieldName,long lastingTime) throws Exception {
        Map<String,Object>fields=TokenUtils.getField_map(obj);
        String secret = null;
        String subject=null;
        String id=null;

        if(fields.containsKey(secretFieldName)){
            secret=(String)fields.get(secretFieldName);
        }

        //secret can not be null
        if(secret==null){
            throw new Exception("you need to assign the secret value");
        }
        if(fields.containsKey(subjectFieldName)){
            subject=(String)fields.get(subjectFieldName);
        }

        //subject can not be null
        if(subject==null){
            throw new Exception("you need to assign the subject value");
        }
        if(fields.containsKey(idFieldName)){
            id=(String)fields.get(idFieldName);
        }

        //if id is null, it will be distributed a random value
        if(id==null){
            id=UUID.randomUUID().toString();
        }

        long now=System.currentTimeMillis();
        Date date=new Date(now);
        JwtBuilder j= Jwts.builder();
        //封装信息在token中
        j.setClaims(fields);
        //设置ID，jwt的唯一标识，设置为一个不重复的值，主要用来作为一次性token,从而回避重放攻击,一般是用户ID
        j.setId(id);
        //设置签发时间
        j.setIssuedAt(date);
        //设置签发人，一般是用户名
        j.setIssuer(subject);
        //设置签名使用的签名算法和签名使用的秘钥
        if(this.algorithm!=null) {
            j.signWith(this.algorithm,secret);
        }else{
            j.signWith(TokenUtils.DefaultAlgorithm,secret);
        }

        //设置token过期时间
        if(lastingTime>=0){
            date=new Date(lastingTime+now);
            j.setExpiration(date);
        }
        return j.compact();
    }

    /**
     *<p>
     *     the static method to create the token, you don't need to
     *     instantiate an obj
     *</p>
     *
     * @param secret: define the secret
     * @param subject: define the subject needs to be the issuer ,
     *                 or no issuer if {@code null}
     * @param lastingTime: the lasting time of token (ms)
     * @return the token string
     * @throws Exception if the secret is not defined
     */
    public static String createToken(String secret,String subject,String id,long lastingTime) throws Exception {
        long now=System.currentTimeMillis();
        Date date=new Date(now);
        JwtBuilder j= Jwts.builder();
        //设置ID，jwt的唯一标识，设置为一个不重复的值，主要用来作为一次性token,从而回避重放攻击
        j.setId(UUID.randomUUID().toString());
        //设置签发时间
        j.setIssuedAt(date);
        //设置签发人
        if(subject!=null) {
            j.setIssuer(subject);
        }
        //设置签名使用的签名算法和签名使用的秘钥
        j.signWith(TokenUtils.DefaultAlgorithm,secret);
        //设置token过期时间
        if(lastingTime>=0){
            date=new Date(lastingTime+now);
            j.setExpiration(date);
        }
        return j.compact();
    }

    /**
     *
     * @param token the token needs to be encrypted
     * @param secret the secret as the key
     * @return the claims
     */
    public static Claims parseToken(String token,String secret){
        if(secret==null){
            return null;
        }
        return Jwts.parser().setSigningKey(secret)
                .parseClaimsJws(token).getBody();
    }

    /**
     *
     * @param token the token needs to be encrypted
     * @param secret the secret as the key
     * @return if the token can be encrypted successfully
     */
    public static boolean verify(String token,String secret){
        Claims claims=parseToken(token,secret);
        return !claims.isEmpty();
    }

    /**
     *
     * @param token the token needs to be refreshed
     * @param time: define the lasting time of the new token
     * @return the new token string
     */
    public static String refreshToken(String token,long time,String secret){
        Claims claims=Jwts.parser().setSigningKey(secret)
                .parseClaimsJws(token).getBody();
        JwtBuilder j=Jwts.builder();
        j.setClaims(claims);
        j.setIssuer(claims.getIssuer());
        j.setId(claims.getId());
        long now=System.currentTimeMillis();
        Date nowDate=new Date(now);
        j.setIssuedAt(nowDate);
        if(time>=0){
            j.setExpiration(new Date(now+time));
        }else{
            j.setExpiration(new Date(now));
        }
        return j.compact();
    }

}
