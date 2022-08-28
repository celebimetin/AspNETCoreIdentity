using IdentityWebApp.Enums;
using IdentityWebApp.Models;
using IdentityWebApp.Services;
using IdentityWebApp.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityWebApp.Controllers
{
    public class HomeController : BaseController
    {
        private readonly EmailSender _emailSender;
        private readonly SmsSender _smsSender;
        private readonly TwoFactorService _twoFactorService;

        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, EmailSender emailSender, SmsSender smsSender, TwoFactorService twoFactorService) : base(userManager, signInManager, null)
        {
            _emailSender = emailSender;
            _smsSender = smsSender;
            _twoFactorService = twoFactorService;
        }

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
                if (_userManager.Users.Any(x => x.PhoneNumber == userViewModel.PhoneNumber))
                {
                    ModelState.AddModelError("", "Bu telefon numarası kayıtlıdır.");
                    return View(userViewModel);
                }
                AppUser user = new AppUser();
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.TwoFactor = 0;
                IdentityResult result = await _userManager.CreateAsync(user, userViewModel.Password);

                if (result.Succeeded)
                {
                    string confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    string link = Url.Action("ConfirmEmail", "Home", new
                    {
                        userId = user.Id,
                        token = confirmationToken
                    }, protocol: HttpContext.Request.Scheme);
                    Helpers.EmailConfirmation.EmailConfirmationSend(link, user.Email);

                    return RedirectToAction("Login");
                }
                else
                {
                    AddModelError(result);
                }
            }
            return View(userViewModel);
        }

        public IActionResult Login(string ReturnUrl = "/")
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

                    if (!_userManager.IsEmailConfirmedAsync(user).Result)
                    {
                        ModelState.AddModelError("", "Email adresiniz onaylanmamıştır. Lütfen e-postanıza gelen doğrulama mailinden e-postanızı doğrulayın.");
                        return View(loginViewModel);
                    }

                    bool userCheck = await _userManager.CheckPasswordAsync(user, loginViewModel.Password);
                    if (userCheck)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                        await _signInManager.SignOutAsync();

                        var result = await _signInManager.PasswordSignInAsync(user, loginViewModel.Password, loginViewModel.RememberMe, false);

                        if (result.RequiresTwoFactor)
                        {
                            if (user.TwoFactor == (int)TwoFactor.Email || user.TwoFactor == (int)TwoFactor.Phone)
                            {
                                HttpContext.Session.Remove("currentTime");
                            }
                            return RedirectToAction("TwoFactorLogin", "Home", new { ReturnUrl = TempData["ReturnUrl"].ToString() });
                        }
                        else
                        {
                            return Redirect(TempData["ReturnUrl"].ToString());
                        }
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

        public async Task<IActionResult> TwoFactorLogin(string ReturnUrl = "/")
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            TempData["ReturnUrl"] = ReturnUrl;

            switch ((TwoFactor)user.TwoFactor)
            {
                case TwoFactor.Email:
                    if (_twoFactorService.TimeLeft(HttpContext) == 0)
                    {
                        return RedirectToAction("Login");
                    }
                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                    HttpContext.Session.SetString("codeVerification", _emailSender.Send(user.Email));
                    break;
                case TwoFactor.Phone:
                    if (_twoFactorService.TimeLeft(HttpContext) == 0)
                    {
                        return RedirectToAction("Login");
                    }
                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                    HttpContext.Session.SetString("codeVerification", _smsSender.Send(user.PhoneNumber));
                    break;
            }
            return View(new TwoFactorLoginViewModel() { TwoFactorType = (TwoFactor)user.TwoFactor, IsRecoverCode = false, IsRememberMe = false, VerificationCode = string.Empty });
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorLogin(TwoFactorLoginViewModel twoFactorLoginViewModel)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            ModelState.Clear();
            bool isSuccessAuth = false;

            if ((TwoFactor)user.TwoFactor == TwoFactor.MicrosoftGoogle)
            {
                Microsoft.AspNetCore.Identity.SignInResult result;

                if (twoFactorLoginViewModel.IsRecoverCode)
                {
                    result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(twoFactorLoginViewModel.VerificationCode);
                }
                else
                {
                    result = await _signInManager.TwoFactorAuthenticatorSignInAsync(twoFactorLoginViewModel.VerificationCode, twoFactorLoginViewModel.IsRememberMe, false);
                }
                if (result.Succeeded)
                {
                    isSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("", "Doğrulama kodu yanlış");
                }
            }
            else if (user.TwoFactor == (sbyte)TwoFactor.Email || user.TwoFactor == (sbyte)TwoFactor.Phone)
            {
                ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                if (twoFactorLoginViewModel.VerificationCode == HttpContext.Session.GetString("codeVerification"))
                {
                    await _signInManager.SignOutAsync();
                    await _signInManager.SignInAsync(user, twoFactorLoginViewModel.IsRememberMe);
                    HttpContext.Session.Remove("currentTime");
                    HttpContext.Session.Remove("codeVerification");

                    isSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("", "Girmiş olduğunuz doğrulama kodu yanlıştır.");
                }
            }

            if (isSuccessAuth)
            {
                return Redirect(TempData["ReturnUrl"].ToString());
            }

            twoFactorLoginViewModel.TwoFactorType = (TwoFactor)user.TwoFactor;
            return View(twoFactorLoginViewModel);
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

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                ViewBag.status = "Email adresiniz onaylanmıştır";
            }
            else
            {
                ViewBag.status = "Bir hata meydana geldi";
            }
            return View();
        }

        public IActionResult FacebookLogin(string ReturnUrl)
        {
            var redirectUrl = Url.Action("ExternalResponce", "Home", new { ReturnUrl = ReturnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Facebook", redirectUrl);
            return new ChallengeResult("Facebook", properties);
        }

        public IActionResult GoogleLogin(string ReturnUrl)
        {
            var redirectUrl = Url.Action("ExternalResponce", "Home", new { ReturnUrl = ReturnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return new ChallengeResult("Google", properties);
        }

        public IActionResult MicrosoftLogin(string ReturnUrl)
        {
            var redirectUrl = Url.Action("ExternalResponce", "Home", new { ReturnUrl = ReturnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Microsoft", redirectUrl);
            return new ChallengeResult("Microsoft", properties);
        }

        public async Task<IActionResult> ExternalResponce(string ReturnUrl = "/")
        {
            ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("Login");
            }
            else
            {
                var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                if (signInResult.Succeeded)
                {
                    return Redirect(ReturnUrl);
                }
                else
                {
                    var user = new AppUser();
                    user.Email = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    var ExternalUserId = info.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                    if (info.Principal.HasClaim(x => x.Type == ClaimTypes.Name))
                    {
                        var userName = info.Principal.FindFirst(ClaimTypes.Name).Value;
                        userName = userName.Replace(' ', '-').ToLower() + ExternalUserId.Substring(5).ToString();
                        user.UserName = userName;
                    }
                    else
                    {
                        user.UserName = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    }

                    var user2 = await _userManager.FindByEmailAsync(user.Email);

                    if (user2 == null)
                    {
                        var createResult = await _userManager.CreateAsync(user);
                        if (createResult.Succeeded)
                        {
                            var loginResult = await _userManager.AddLoginAsync(user, info);
                            if (loginResult.Succeeded)
                            {
                                await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                                return Redirect(ReturnUrl);
                            }
                            else
                            {
                                AddModelError(loginResult);
                            }
                        }
                        else
                        {
                            AddModelError(createResult);
                        }
                    }
                    else
                    {
                        var loginResult = await _userManager.AddLoginAsync(user2, info);
                        await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                        return Redirect(ReturnUrl);
                    }
                }
            }

            var errors = ModelState.Values.SelectMany(x => x.Errors).Select(y => y.ErrorMessage).ToList();
            return View("Error", errors);
        }

        public IActionResult Error()
        {
            return View();
        }

        public IActionResult Policy()
        {
            return View();
        }

        [HttpGet]
        public JsonResult AgainSendEmail()
        {
            try
            {
                var user = _signInManager.GetTwoFactorAuthenticationUserAsync().Result;
                HttpContext.Session.SetString("codeVerification", _emailSender.Send(user.Email));
                return Json(true);
            }
            catch (Exception)
            {
                return Json(false);
            }
        }
    }
}