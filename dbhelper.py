import datetime
import logging

from db import SessionFactory
from model import GroupConfig, BlacklistUser, RecaptchaLog, RecaptchaLogAction


def get_user(user_id):
    with SessionFactory() as session:
        user = session.query(BlacklistUser).filter_by(user_id=user_id).first()
        if user is None:
            return None
        else:
            return user


def get_user_status(user_id):
    with SessionFactory() as session:
        user = session.query(BlacklistUser).filter_by(user_id=user_id).first()
        if user is None:
            return 0
        else:
            return 1


def update_last_try(time, user_id):
    with SessionFactory() as session:
        user = session.query(BlacklistUser).filter_by(user_id=user_id).first()
        if user is None:
            logging.error('User not found')
        else:
            user.last_attempt = time
            session.commit()


def try_count_plus_one(user_id):
    with SessionFactory() as session:
        user = session.query(BlacklistUser).filter_by(user_id=user_id).first()
        if user is None:
            logging.error('User not found')
        else:
            user.attempt_count += 1
            session.commit()


def new_blacklist(time, user_id):
    # tested
    with SessionFactory() as session:
        user = BlacklistUser(user_id=user_id, last_attempt=time)
        session.add(user)
        session.commit()


def get_try_count(user_id):
    with SessionFactory() as session:
        user = session.query(BlacklistUser).filter_by(user_id=user_id).first()
        if user is None:
            return 0
        else:
            return user.attempt_count


def get_all_user_ids():
    with SessionFactory() as session:
        user = session.query(BlacklistUser).all()
        if user is None:
            return 0
        else:
            return [i.user_id for i in user]


def delete_user(user_id):
    with SessionFactory() as session:
        user = session.query(BlacklistUser).filter_by(user_id=user_id).first()
        if user is None:
            logging.error('User not found')
        else:
            session.delete(user)
            session.commit()


def get_group_config(group_id, field: str = 'all'):
    with SessionFactory() as session:
        group = session.query(GroupConfig).filter_by(chat_id=group_id).first()
        if group is None:
            return None
        else:
            if field == 'challenge_failed_action':
                return group.failed_action
            elif field == 'challenge_timeout_action':
                return group.timeout_action
            elif field == 'challenge_timeout':
                return group.timeout
            elif field == 'challenge_type':
                return group.challenge_type
            elif field == 'enable_global_blacklist':
                return group.global_blacklist
            elif field == 'enable_third_party_blacklist':
                return group.third_party_blacklist
            elif field == 'all':
                return {'challenge_failed_action': group.failed_action,
                        'challenge_timeout_action': group.timeout_action,
                        'challenge_timeout': group.timeout, 'challenge_type': group.challenge_type,
                        'enable_global_blacklist': group.global_blacklist,
                        'enable_third_party_blacklist': group.third_party_blacklist}
            else:
                return None


def new_group_config(group_id):
    with SessionFactory() as session:
        group = GroupConfig(chat_id=group_id)
        session.add(group)
        session.commit()


def set_group_config(group_id, key, value):
    key = key.lower()
    value = value.lower()
    # tested 80% passed
    with SessionFactory() as session:
        group = session.query(GroupConfig).filter_by(chat_id=group_id).first()
        if group is None:
            new_group_config(group_id)
        else:
            if key == 'challenge_failed_action':
                group.failed_action = value
            elif key == 'challenge_timeout_action':
                group.timeout_action = value
            elif key == 'challenge_timeout':
                group.timeout = value
            elif key == 'challenge_type':
                group.challenge_type = value
            elif key == 'enable_global_blacklist':
                group.global_blacklist = value
            elif key == 'enable_third_party_blacklist':
                group.third_party_blacklist = value
            else:
                return False
            session.commit()
    return True


def log_recaptcha(challenge_id, user_id, chat_id, ip_addr, user_agent, action: RecaptchaLogAction):
    # 先根据 challenge_id, user_id, chat_id, ip_addr, action 查询是否已经存在记录 如果存在则什么都不做
    # 如果不存在则插入记录
    with SessionFactory() as session:
        log = session.query(RecaptchaLog).filter_by(challenge_id=challenge_id, user_id=user_id, group_id=chat_id,
                                                    ip_addr=ip_addr, action=action).first()
        if log is None:
            log = RecaptchaLog(challenge_id=challenge_id, user_id=user_id, group_id=chat_id, ip_addr=ip_addr,
                               user_agent=user_agent, action=action)
        session.add(log)
        session.commit()


def get_logs_by_challenge_id(challenge_id):
    with SessionFactory() as session:
        # limit to last 5 logs
        logs = session.query(RecaptchaLog).filter_by(challenge_id=challenge_id).order_by(
            RecaptchaLog.created_at.desc()).limit(5).all()
        return logs


if __name__ == '__main__':
    ...
