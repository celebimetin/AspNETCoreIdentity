﻿using IdentityWebApp.Enums;
using IdentityWebApp.Models;
using IdentityWebApp.Services;
using IdentityWebApp.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityWebApp.Controllers
{
    [Authorize]
    public class MemberController : BaseController
    {
        private readonly TwoFactorService _twoFactorService;

        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, TwoFactorService twoFactorService) : base(userManager, signInManager, null) 
        {
            _twoFactorService = twoFactorService;
        }

        public IActionResult Index()
        {
            var user = _userManager.FindByNameAsync(User.Identity.Name).Result;
            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            return View(userViewModel);
        }

        public IActionResult UserEdit()
        {
            var user = CurrentUser;
            var userViewModel = user.Adapt<UserViewModel>();
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));
            return View(userViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> UserEdit(UserViewModel userViewModel, IFormFile userPicture)
        {
            ModelState.Remove("Password");

            if (ModelState.IsValid)
            {
                var user = CurrentUser;
                var phone = _userManager.GetPhoneNumberAsync(user).Result;
                if (phone != userViewModel.PhoneNumber)
                {
                    if (_userManager.Users.Any(x => x.PhoneNumber == userViewModel.PhoneNumber))
                    {
                        ModelState.AddModelError("", "Bu telefon numarası kayıtlıdır.");
                        return View(userViewModel);
                    }
                }
                if (userPicture != null && userPicture.Length > 0)
                {
                    var fileName = Guid.NewGuid().ToString() + Path.GetExtension(userPicture.FileName);
                    var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/Picture", fileName);

                    using (var stream = new FileStream(path, FileMode.Create))
                    {
                        await userPicture.CopyToAsync(stream);
                        user.Picture = "/Picture/" + fileName;
                    }
                }
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.City = userViewModel.City;
                user.BirthDay = userViewModel.BirthDay;
                user.Gender = (int)userViewModel.Gender;

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    await _userManager.UpdateSecurityStampAsync(user);

                    await _signInManager.SignOutAsync();
                    await _signInManager.SignInAsync(user, true);

                    ViewBag.success = "true";
                }
                else
                {
                    AddModelError(result);
                }
            }
            return View(userViewModel);
        }

        public IActionResult PasswordChange()
        {
            return View();
        }

        [HttpPost]
        public IActionResult PasswordChange(PasswordChangeViewModel passwordChange)
        {
            if (ModelState.IsValid)
            {
                var user = CurrentUser;
                if (user != null)
                {
                    bool exist = _userManager.CheckPasswordAsync(user, passwordChange.PasswordOld).Result;
                    if (exist)
                    {
                        var result = _userManager.ChangePasswordAsync(user, passwordChange.PasswordOld, passwordChange.PasswordNew).Result;
                        if (result.Succeeded)
                        {
                            _userManager.UpdateSecurityStampAsync(user);

                            _signInManager.SignOutAsync();
                            _signInManager.PasswordSignInAsync(user, passwordChange.PasswordNew, true, false);

                            ViewBag.success = "true";
                        }
                        else
                        {
                            AddModelError(result);
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "Eski şifreniz yanlıştır.");
                    }
                }
            }
            return View(passwordChange);
        }

        public void Logout()
        {
            _signInManager.SignOutAsync();
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        [Authorize(Roles = "editor,admin")]
        public IActionResult Editor()
        {
            return View();
        }

        [Authorize(Roles = "manager,admin")]
        public IActionResult Manager()
        {
            return View();
        }

        [Authorize(Policy = "AnkaraPolicy")]
        public IActionResult ClaimAuthorize()
        {
            return View();
        }

        public async Task<IActionResult> ExchangeRedirect()
        {
            var result = User.HasClaim(x => x.Type == "ExpireDateExchange");
            if (!result)
            {
                var ExpireDateExchange = new Claim("ExpireDateExchange", DateTime.Now.AddDays(30).Date.ToShortDateString(), ClaimValueTypes.String, "Internal");

                await _userManager.AddClaimAsync(CurrentUser, ExpireDateExchange);
                await _signInManager.SignOutAsync();
                await _signInManager.SignInAsync(CurrentUser, true);
            }
            return RedirectToAction("Exchange");
        }

        [Authorize(Policy = "ExchangePolicy")]
        public IActionResult Exchange()
        {
            return View();
        }

        public async Task<IActionResult> TwoFactorWithAuthenticator()
        {
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(CurrentUser);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(CurrentUser);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(CurrentUser);
            }
            AuthenticatorViewModel authenticatorViewModel = new AuthenticatorViewModel();
            authenticatorViewModel.SharedKey = unformattedKey;
            authenticatorViewModel.AuthenticatorUri = _twoFactorService.GenerateQrCodeUri(CurrentUser.Email, unformattedKey);

            return View(authenticatorViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorWithAuthenticator(AuthenticatorViewModel authenticatorViewModel)
        {
            var verificationCode = authenticatorViewModel.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);
            var is2FATokenvalid = await _userManager.VerifyTwoFactorTokenAsync(CurrentUser, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (is2FATokenvalid)
            {
                CurrentUser.TwoFactorEnabled = true;
                CurrentUser.TwoFactor = (sbyte)TwoFactor.MicrosoftGoogle;
                var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(CurrentUser, 5);
                TempData["recoveryCodes"] = recoveryCodes;
                TempData["message"] = "İki adımlı kimlik doğrulama tipiniz Microsoft/Google Authenticator olarak belirlenmiştir.";

                return RedirectToAction("TwoFactorAuth");
            }
            else
            {
                ModelState.AddModelError("", "Girdiğiniz doğrulama kodu yanlıştır.");
                return View(authenticatorViewModel);
            }
        }

        public IActionResult TwoFactorAuth()
        {
            return View(new AuthenticatorViewModel() { TwoFactorType = (TwoFactor)CurrentUser.TwoFactor });
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorAuth(AuthenticatorViewModel authenticatorViewModel)
        {
            switch (authenticatorViewModel.TwoFactorType)
            {
                case TwoFactor.None:
                    CurrentUser.TwoFactorEnabled = false;
                    CurrentUser.TwoFactor = (sbyte)TwoFactor.None;
                    TempData["message"] = "İki adımlı kimlik doğrulama tipiniz hiçbiri olarak belirlenmiştir.";
                    break;
                case TwoFactor.Phone:
                    if (string.IsNullOrEmpty(CurrentUser.PhoneNumber))
                    {
                        ViewBag.warning = "Telefon numaranız yanlış veya belirtilmemiştir.";
                    }
                    CurrentUser.TwoFactorEnabled = true;
                    CurrentUser.TwoFactor = (sbyte)TwoFactor.Phone;
                    TempData["message"] = "İki adımlı kimlik doğrulama tipiniz Telefon olarak belirlenmiştir.";
                    break;
                case TwoFactor.Email:
                    CurrentUser.TwoFactorEnabled = true;
                    CurrentUser.TwoFactor = (sbyte)TwoFactor.Email;
                    TempData["message"] = "İki adımlı kimlik doğrulama tipiniz Email olarak belirlenmiştir.";
                    break;
                case TwoFactor.MicrosoftGoogle:
                    return RedirectToAction("TwoFactorWithAuthenticator");
                default:
                    break;
            }
            await _userManager.UpdateAsync(CurrentUser);

            return View(authenticatorViewModel);
        }
    }
}