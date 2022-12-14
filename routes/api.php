<?php

use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::get('users',[UserController::class,'index'])->middleware('jwtVerify');
Route::post('users',[UserController::class,'deleteUser'])->middleware('jwtVerify');
Route::put('users',[UserController::class,'updateUser'])->middleware('jwtVerify');
Route::group([
    'middleware' => ['api','cors'],
],function($router){
    Route::post('login',[AuthController::class,'login'])->name('login');
    Route::post('register',[AuthController::class,'register']);
    Route::get('logout',[AuthController::class,'logout']);
});