<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $user = User::all();
        return response()->json([
            'users'=>$user
        ],200);
    }

    public function updateUser(Request $request)
     {
        $exist = DB::table('users')->where('id', $request->id)->first();
  
        if(!$exist){
            return response()->json([
                'msg'=>"the User Not existed"
            ],404);
        }

            $usersUp = User::findOrFail($request->id);
            $usersUp->name = $request->name;
            $usersUp->email = $request->email;
            $usersUp->cell = $request->cell;
            $usersUp->save();
        return response()->json([
            "Users" => $usersUp
        ]);
     }

    public function deleteUser(Request $request)
    {
       $exist = DB::table('users')->where('id', $request->id)->first();
 
       if(!$exist){
           return response()->json([
               'msg'=>"the User Not existed"
           ],404);
       }
       
       $userDelete = User::destroy($request->id);
       return response()->json([
           'msg'=> 'User delete',
           'user'=> $userDelete 
       ]);
    }
    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\User  $user
     * @return \Illuminate\Http\Response
     */
    public function show(User $user)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\User  $user
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, User $user)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\User  $user
     * @return \Illuminate\Http\Response
     */
    public function destroy(User $user)
    {
        //
    }
}
