<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\loginRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register (Request $request){
        $this->validate($request,[
            'name' => 'required|max:200',
            'email'=>'required|email|max:255|unique:users',
            'cell' => 'required|min:8',
            'password'=>'required|min:6'
            
        ]);
            $user = new User;
            $user->name = $request->name;
            $user->email = $request->email;
            $user->cell = $request->cell;
            $user->password = Hash::make($request->password);
            $user->save();
        
        $token = JWTAuth::fromUser($user);
        
        return response()->json([
            'user' => $user,
            'token' => $token
        ],201);
    }

    public function login (loginRequest $request){
        $credentials = $request->only('email','password');
        try{
            if($token = JWTAuth::attempt($credentials)){
                return response()->json([
                    'Credenciales invalidas'
                ],400);
            }

        }catch(JWTException $error){
            return response()->json([
                'error' => $error,
            ],500);
        }
        response()->json([compact('token')]);
    }

}
