package com.yumyapps.jwt.validator;

import com.google.common.base.Joiner;
import lombok.extern.slf4j.Slf4j;
import org.passay.*;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Arrays;

import static com.yumyapps.jwt.constants.Constants.INVALID_PASSWORD;

@Slf4j
public class StrictPasswordValidator implements ConstraintValidator<StrictPassword, String> {


    @Override
    public boolean isValid(final String value, ConstraintValidatorContext context) {
        PasswordValidator validator = new PasswordValidator(Arrays.asList(

                new LengthRule(8, 30),
                new CharacterRule(EnglishCharacterData.Digit, 2),
                new CharacterRule(EnglishCharacterData.Special, 1),
                new WhitespaceRule()));
        final RuleResult result = validator.validate(new PasswordData(value));
        if (result.isValid()) {
            log.info("Password validation success");
            return true;
        }

        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(Joiner.on(",").join(validator.getMessages(result))).addConstraintViolation();
        log.error("Password validation Error");
        return false;
    }

    @Override
    public void initialize(StrictPassword arg0) {

    }
}
