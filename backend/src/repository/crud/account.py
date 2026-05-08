import typing

import sqlalchemy
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.db.account import Account
from src.models.schemas.account import (
    AccountInCreate,
    AccountInLogin,
    AccountInUpdate,
)
from src.repository.crud.base import BaseCRUDRepository
from src.securities.hashing.password import pwd_generator
from src.utilities.exceptions.database import (
    EntityAlreadyExists,
    EntityDoesNotExist,
)
from src.utilities.exceptions.password import PasswordDoesNotMatch


class AccountCRUDRepository(BaseCRUDRepository):

    async def create_account(self, account_create: AccountInCreate) -> Account:
        await self.is_username_taken(account_create.username)
        await self.is_email_taken(account_create.email)

        salt = pwd_generator.generate_salt

        new_account = Account(
            username=account_create.username,
            email=account_create.email,
            is_logged_in=True,
            hash_salt=salt,
            hashed_password=pwd_generator.generate_hashed_password(
                hash_salt=salt,
                new_password=account_create.password,
            ),
        )

        self.async_session.add(new_account)

        await self.async_session.commit()
        await self.async_session.refresh(new_account)

        return new_account

    async def read_accounts(self) -> typing.Sequence[Account]:
        result = await self.async_session.execute(select(Account))
        return result.scalars().all()

    async def read_account_by_id(self, id: int) -> Account:
        result = await self.async_session.execute(
            select(Account).where(Account.id == id)
        )

        account = result.scalar_one_or_none()

        if account is None:
            raise EntityDoesNotExist(f"Account with id `{id}` does not exist!")

        return account

    async def read_account_by_username(self, username: str) -> Account:
        result = await self.async_session.execute(
            select(Account).where(Account.username == username)
        )

        account = result.scalar_one_or_none()

        if account is None:
            raise EntityDoesNotExist(
                f"Account with username `{username}` does not exist!"
            )

        return account

    async def read_account_by_email(self, email: str) -> Account:
        result = await self.async_session.execute(
            select(Account).where(Account.email == email)
        )

        account = result.scalar_one_or_none()

        if account is None:
            raise EntityDoesNotExist(
                f"Account with email `{email}` does not exist!"
            )

        return account

    async def read_user_by_password_authentication(
        self,
        account_login: AccountInLogin,
    ) -> Account:

        result = await self.async_session.execute(
            select(Account).where(
                Account.username == account_login.username,
                Account.email == account_login.email,
            )
        )

        db_account = result.scalar_one_or_none()

        if db_account is None:
            raise EntityDoesNotExist("Wrong username or email!")

        is_authenticated = pwd_generator.is_password_authenticated(
            hash_salt=db_account.hash_salt,
            password=account_login.password,
            hashed_password=db_account.hashed_password,
        )

        if not is_authenticated:
            raise PasswordDoesNotMatch("Password does not match!")

        return db_account

    async def update_account_by_id(
        self,
        id: int,
        account_update: AccountInUpdate,
    ) -> Account:

        account = await self.read_account_by_id(id)

        update_data = account_update.dict(exclude_unset=True)

        if "username" in update_data:
            account.username = update_data["username"]

        if "email" in update_data:
            account.email = update_data["email"]   # FIXED BUG

        if "password" in update_data:
            salt = pwd_generator.generate_salt

            account.hash_salt = salt
            account.hashed_password = (
                pwd_generator.generate_hashed_password(
                    hash_salt=salt,
                    new_password=update_data["password"],
                )
            )

        await self.async_session.commit()
        await self.async_session.refresh(account)

        return account

    async def delete_account_by_id(self, id: int) -> str:
        account = await self.read_account_by_id(id)

        await self.async_session.delete(account)
        await self.async_session.commit()

        return f"Account with id '{id}' was deleted successfully!"

    async def is_username_taken(self, username: str) -> bool:
        result = await self.async_session.execute(
            select(Account.id).where(Account.username == username)
        )

        if result.scalar_one_or_none():
            raise EntityAlreadyExists(
                f"The username `{username}` is already taken!"
            )

        return False

    async def is_email_taken(self, email: str) -> bool:
        result = await self.async_session.execute(
            select(Account.id).where(Account.email == email)
        )

        if result.scalar_one_or_none():
            raise EntityAlreadyExists(
                f"The email `{email}` is already registered!"
            )

        return False
