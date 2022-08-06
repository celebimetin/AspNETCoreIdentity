using IdentityWebApp.Models;
using IdentityWebApp.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace IdentityWebApp.Controllers
{
    public class HomeController : BaseController
    {
        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager) : base(userManager, signInManager, null) { }

        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Member");
            }
            return View();
        }

        public IActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(UserViewModel userViewModel)
        {
            if (ModelState.IsValid)
            {
                AppUser user = new AppUser();
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                IdentityResult result = await _userManager.CreateAsync(user, userViewModel.Password);

                if (result.Succeeded)
                {
                    return RedirectToAction("Login");
                }
                else
                {
                    AddModelError(result);
                }
            }
            return View(userViewModel);
        }

        public IActionResult Login(string ReturnUrl)
        {
            TempData["ReturnUrl"] = ReturnUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(loginViewModel.Email);
                if (user != null)
                {
                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        ModelState.AddModelError("", "Hesabınızı bir süreliğine kilitlenmiştir. Lütfen daha sonra tekrar deneyiniz.");
                        return View(loginViewModel);
                    }

                    await _signInManager.SignOutAsync();
                    Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(user, loginViewModel.Password, loginViewModel.RememberMe, false);

                    if (result.Succeeded)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);

                        if (TempData["ReturnUrl"] != null)
                        {
                            return Redirect(TempData["ReturnUrl"].ToString());
                        }
                        return RedirectToAction("Index", "Home");
                    }
                    else
                    {
                        await _userManager.AccessFailedAsync(user);

                        int fail = await _userManager.GetAccessFailedCountAsync(user);

                        ModelState.AddModelError("", $"{fail} kez başarısız giriş yapıldı.");
                        if (fail == 3)
                        {
                            await _userManager.SetLockoutEndDateAsync(user, new DateTimeOffset(DateTime.Now.AddMinutes(15)));

                            ModelState.AddModelError("", $"Hesabınız 3 başarısız girişten dolayı 15 dakika süreyle kitlenmiştir. Lüften daha sonra tekrar deneyiniz.");
                        }
                        else
                        {
                            ModelState.AddModelError("", "Email adresiniz veya şifresiniz yanlış");
                        }
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Geçersiz email adresi veya şifre");
                }
            }
            return View(loginViewModel);
        }

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public IActionResult ResetPassword(PasswordResetViewModel passwordResetViewModel)
        {
            var user = _userManager.FindByEmailAsync(passwordResetViewModel.Email).Result;
            if (user != null)
            {
                string passwordResetToken = _userManager.GeneratePasswordResetTokenAsync(user).Result;

                string passwordResetLink = Url.Action("ResetPasswordConfirm", "Home", new
                {
                    userId = user.Id,
                    token = passwordResetToken,
                }, HttpContext.Request.Scheme);

                Helpers.PasswordResetHelper.PasswordResetSendEmail(passwordResetLink, user.Email);

                ViewBag.status = "success";
            }
            else
            {
                ModelState.AddModelError("", "Sistemde kayıtlı mail adresi bulunamadı.");
            }
            return View(passwordResetViewModel);
        }

        public IActionResult ResetPasswordConfirm(string userId, string token)
        {
            TempData["userId"] = userId;
            TempData["token"] = token;

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPasswordConfirm([Bind("NewPassword")] PasswordResetViewModel passwordResetViewModel)
        {
            string token = TempData["token"].ToString();
            string userId = TempData["userId"].ToString();

            var user = await _userManager.FindByIdAsync(userId);

            if (user != null)
            {
                var result = await _userManager.ResetPasswordAsync(user, token, passwordResetViewModel.NewPassword);

                if (result.Succeeded)
                {
                    await _userManager.UpdateSecurityStampAsync(user);
                    ViewBag.status = "success";
                }
                else
                {
                    AddModelError(result);
                }
            }
            return View(passwordResetViewModel);
        }
    }
}