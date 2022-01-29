﻿namespace BlazorShop.Application.Validators.ClotheValidator
{
    public class DeleteClotheCommandValidator : AbstractValidator<DeleteClotheCommand>
    {
        public DeleteClotheCommandValidator()
        {
            _ = RuleFor(v => v.Id)
                .GreaterThan(0).WithMessage("Id must be greater than 0");
        }
    }
}
